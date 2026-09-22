"""PEP: valida a cadeia, extrai c, recomputa c' e compara.

A extracao da extensao e feita por percurso DER puro, sem subprocess e sem
parsing de texto. Isso torna a verificacao deterministica e sustenta a promessa
do artigo: local, sem estado e sem contato com a ACE.
"""
import calendar
import hmac
import os
import subprocess
import sys
import time

_AQUI = os.path.dirname(os.path.abspath(__file__))
_RAIZ = os.path.dirname(_AQUI)
for _p in (os.path.join(_RAIZ, "intent"), os.path.join(_RAIZ, "ace")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from intent import Intencao                                        # noqa: E402
from extensao import decodificar_extensao, OID_INTENT, VERSAO      # noqa: E402


class Rejeitado(Exception):
    pass


# ------------------------------------------------------------- DER minimo

def _tlv(buf, off):
    """Le um TLV. Retorna (tag, inicio_do_valor, fim_do_valor, proximo_off)."""
    if off + 2 > len(buf):
        raise Rejeitado("DER truncado")
    tag = buf[off]; off += 1
    n = buf[off]; off += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or off + k > len(buf):
            raise Rejeitado("comprimento DER invalido")
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    if off + n > len(buf):
        raise Rejeitado("valor DER excede o buffer")
    return tag, off, off + n, off + n


def _filhos(buf, ini, fim):
    """Itera os TLV filhos de um construtor."""
    off = ini
    while off < fim:
        tag, vi, vf, prox = _tlv(buf, off)
        yield tag, vi, vf
        off = prox


def _oid_para_der(oid: str) -> bytes:
    """Codifica um OID pontilhado no corpo DER, sem tag e sem comprimento."""
    partes = [int(x) for x in oid.split(".")]
    saida = bytearray([40 * partes[0] + partes[1]])
    for n in partes[2:]:
        if n == 0:
            saida.append(0)
            continue
        pilha = []
        while n:
            pilha.append(n & 0x7F)
            n >>= 7
        pilha.reverse()
        for i, b in enumerate(pilha):
            saida.append(b | (0x80 if i < len(pilha) - 1 else 0))
    return bytes(saida)


def extrair_extensao_critica(cert_der: bytes, oid: str = OID_INTENT):
    """Percorre o certificado e devolve (valor_der, critica).

    Estrutura percorrida:
      Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
      TBSCertificate ::= SEQUENCE { ..., [3] EXPLICIT Extensions OPTIONAL }
      Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
                               extnValue OCTET STRING }
    """
    alvo = _oid_para_der(oid)

    _, cvi, cvf, _ = _tlv(cert_der, 0)                 # Certificate
    tbs = next(_filhos(cert_der, cvi, cvf), None)      # tbsCertificate
    if tbs is None:
        raise Rejeitado("certificado sem tbsCertificate")
    _, tvi, tvf = tbs

    exts = None
    for tag, vi, vf in _filhos(cert_der, tvi, tvf):
        if tag == 0xA3:                                # [3] EXPLICIT Extensions
            inner = next(_filhos(cert_der, vi, vf), None)
            if inner and inner[0] == 0x30:
                exts = (inner[1], inner[2])
            break
    if exts is None:
        raise Rejeitado("certificado sem bloco de extensoes")

    for tag, vi, vf in _filhos(cert_der, *exts):
        if tag != 0x30:
            continue
        campos = list(_filhos(cert_der, vi, vf))
        if not campos or campos[0][0] != 0x06:
            continue
        if cert_der[campos[0][1]:campos[0][2]] != alvo:
            continue
        critica = False
        valor = None
        for t, a, b in campos[1:]:
            if t == 0x01:                              # BOOLEAN critical
                critica = cert_der[a:b] != b"\x00"
            elif t == 0x04:                            # OCTET STRING extnValue
                valor = cert_der[a:b]
        if valor is None:
            raise Rejeitado("extensao sem extnValue")
        return valor, critica

    raise Rejeitado("extensao de intencao ausente")


# ---------------------------------------------------------------- validade

def _epoch_utc(texto: str) -> float:
    """Converte 'Aug 14 18:31:36 2026 GMT' para epoch UTC.

    Usa calendar.timegm, e nao time.mktime, porque mktime interpreta em hora
    local e produziria deslocamento de fuso na janela de validade.
    """
    t = time.strptime(texto.replace(" GMT", "").strip(), "%b %d %H:%M:%S %Y")
    return calendar.timegm(t)


def _janela(cert_der: bytes):
    r = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-dates"],
                       input=cert_der, capture_output=True, timeout=10)
    nb = na = None
    for l in r.stdout.decode(errors="replace").splitlines():
        if l.startswith("notBefore="):
            nb = l.split("=", 1)[1]
        elif l.startswith("notAfter="):
            na = l.split("=", 1)[1]
    if nb is None or na is None:
        raise Rejeitado("nao foi possivel ler a validade")
    return _epoch_utc(nb), _epoch_utc(na)


# ------------------------------------------------------------- verificacao

def verificar(cert_der: bytes, contexto: dict, operacao: str,
              politica_esperada: bytes, ca_pem: str = None,
              checar_validade: bool = True, exigir_critica: bool = True):
    """Retorna (aceito: bool, motivo: str). Falha fechada em qualquer excecao."""
    try:
        if ca_pem:
            r = subprocess.run(["openssl", "verify", "-CAfile", ca_pem],
                               input=cert_der, capture_output=True, timeout=10)
            # O openssl CLI nao conhece o OID privado da extensao critica e
            # a rejeita como nao tratada. E falha fechada esperada; quem sabe
            # interpretar a extensao e o PEP.
            tolerados = (b"has expired", b"unhandled critical extension")
            motivo = r.stderr.lower()
            if r.returncode != 0 and not any(t in motivo for t in tolerados):
                return False, "cadeia invalida"

        if checar_validade:
            nb, na = _janela(cert_der)
            agora = time.time()
            if agora < nb:
                return False, "certificado ainda nao valido"
            if agora > na:
                return False, "certificado expirado"

        der_ext, critica = extrair_extensao_critica(cert_der)
        if exigir_critica and not critica:
            return False, "extensao de intencao nao esta marcada como critica"

        versao, c, pol = decodificar_extensao(der_ext)
        if versao != VERSAO:
            return False, f"versao de esquema desconhecida: {versao}"
        if not hmac.compare_digest(pol, politica_esperada):
            return False, "politica divergente"

        # recomputa c' a partir do contexto OBSERVADO, nunca do declarado
        i_linha = Intencao(**contexto)
        if not hmac.compare_digest(c, i_linha.compromisso()):
            return False, "compromisso de intencao nao confere"

        if operacao not in i_linha.A:
            return False, f"operacao '{operacao}' fora do escopo A"

        return True, "ok"

    except Rejeitado as e:
        return False, str(e)
    except Exception as e:                                  # falha fechada
        return False, f"erro de verificacao: {type(e).__name__}: {e}"