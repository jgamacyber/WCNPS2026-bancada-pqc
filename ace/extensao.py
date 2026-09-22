#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Codificacao e decodificacao DER da extensao de intencao do IDEIA-PQ.

    IntencaoExt ::= SEQUENCE {
        versao      INTEGER,             -- versao do esquema de canonizacao
        canon       UTF8String,          -- "RFC8785", 7 caracteres
        compromisso OCTET STRING (48),   -- c = SHA-384(enc(I))
        politica    OCTET STRING (48)    -- SHA-384 da politica vigente
    }

Tamanhos, conferidos pelo teste test_tamanhos_do_artigo:

    corpo da SEQUENCE   112 bytes   3 + 9 + 50 + 50
    SEQUENCE completa   114 bytes   30 70 + 112
    Extension X.509     134 bytes   OID(12) + critical(3) + OCTET STRING(116)
                                    envolvidos por SEQUENCE com comprimento longo

Sao esses 114 e 134 que aparecem na Secao IV-B do artigo. Se algum campo
mudar de tamanho, o teste quebra e o numero do artigo precisa ser corrigido
junto. E de proposito: numero de artigo que ninguem verifica vira numero errado.
"""

OID_INTENT = "1.3.6.1.4.1.99999.1.1"
VERSAO = 1
CANON = "RFC8785"
TAM_HASH = 48          # SHA-384


class ErroExtensao(ValueError):
    pass


# ------------------------------------------------------------------- DER cru

def _tlv(tag: int, corpo: bytes) -> bytes:
    n = len(corpo)
    if n < 0x80:
        cab = bytes([tag, n])
    else:
        comp = n.to_bytes((n.bit_length() + 7) // 8, "big")
        cab = bytes([tag, 0x80 | len(comp)]) + comp
    return cab + corpo


def _inteiro(v: int) -> bytes:
    if v < 0:
        raise ErroExtensao("versao negativa")
    corpo = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return _tlv(0x02, corpo)


def _oid(pontilhado: str) -> bytes:
    partes = [int(x) for x in pontilhado.split(".")]
    if len(partes) < 2:
        raise ErroExtensao("OID curto demais")
    corpo = bytearray([40 * partes[0] + partes[1]])
    for n in partes[2:]:
        if n == 0:
            corpo.append(0)
            continue
        pilha = []
        while n:
            pilha.append(n & 0x7F)
            n >>= 7
        pilha.reverse()
        for i, b in enumerate(pilha):
            corpo.append(b | (0x80 if i < len(pilha) - 1 else 0))
    return _tlv(0x06, bytes(corpo))


def _ler_tlv(buf: bytes, off: int):
    if off + 2 > len(buf):
        raise ErroExtensao("DER truncado")
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or off + k > len(buf):
            raise ErroExtensao("comprimento DER invalido")
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    if off + n > len(buf):
        raise ErroExtensao("valor DER excede o buffer")
    return tag, buf[off:off + n], off + n


# ----------------------------------------------------------- corpo da extensao

def codificar_extensao(compromisso: bytes, politica: bytes,
                       versao: int = VERSAO) -> bytes:
    """Devolve a SEQUENCE de 114 bytes que vai dentro do extnValue."""
    if len(compromisso) != TAM_HASH:
        raise ErroExtensao(f"compromisso deve ter {TAM_HASH} bytes, "
                           f"veio com {len(compromisso)}")
    if len(politica) != TAM_HASH:
        raise ErroExtensao(f"politica deve ter {TAM_HASH} bytes, "
                           f"veio com {len(politica)}")
    corpo = (_inteiro(versao)
             + _tlv(0x0C, CANON.encode("utf-8"))
             + _tlv(0x04, compromisso)
             + _tlv(0x04, politica))
    return _tlv(0x30, corpo)


def decodificar_extensao(der: bytes):
    """Devolve (versao, compromisso, politica). Falha alto em qualquer desvio.

    O PEP depende desta funcao para recompor c. Ser permissivo aqui
    transformaria um certificado malformado em aceitacao silenciosa, entao
    todo campo inesperado e erro.
    """
    tag, corpo, fim = _ler_tlv(der, 0)
    if tag != 0x30:
        raise ErroExtensao("extensao nao e SEQUENCE")
    if fim != len(der):
        raise ErroExtensao("bytes sobrando depois da SEQUENCE")

    off = 0
    t, v, off = _ler_tlv(corpo, off)
    if t != 0x02:
        raise ErroExtensao("campo 1 deveria ser INTEGER")
    versao = int.from_bytes(v, "big")

    t, v, off = _ler_tlv(corpo, off)
    if t != 0x0C:
        raise ErroExtensao("campo 2 deveria ser UTF8String")
    canon = v.decode("utf-8")
    if canon != CANON:
        raise ErroExtensao(f"esquema de canonizacao desconhecido: {canon}")

    t, compromisso, off = _ler_tlv(corpo, off)
    if t != 0x04 or len(compromisso) != TAM_HASH:
        raise ErroExtensao("compromisso ausente ou com tamanho errado")

    t, politica, off = _ler_tlv(corpo, off)
    if t != 0x04 or len(politica) != TAM_HASH:
        raise ErroExtensao("politica ausente ou com tamanho errado")

    if off != len(corpo):
        raise ErroExtensao("campos extras na extensao")
    return versao, compromisso, politica


# ----------------------------------------------- Extension X.509 completa

def codificar_extension_x509(compromisso: bytes, politica: bytes,
                             versao: int = VERSAO, critica: bool = True) -> bytes:
    """Extension ::= SEQUENCE { extnID, critical, extnValue }, 134 bytes."""
    interno = codificar_extensao(compromisso, politica, versao)
    corpo = _oid(OID_INTENT)
    if critica:
        corpo += _tlv(0x01, b"\xff")
    corpo += _tlv(0x04, interno)
    return _tlv(0x30, corpo)


def config_openssl(compromisso_hex: str, politica_hex: str,
                   versao: int = VERSAO) -> str:
    """Linha pronta para o arquivo de configuracao do 'openssl x509 -extfile'.

    O DER inteiro vai literal, porque o OpenSSL nao conhece este OID e nao
    saberia montar a estrutura sozinho.
    """
    interno = codificar_extensao(bytes.fromhex(compromisso_hex),
                                 bytes.fromhex(politica_hex), versao)
    return f"{OID_INTENT}=critical,DER:{interno.hex().upper()}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        # uso: extensao.py <compromisso_hex> <politica_hex>
        print(config_openssl(sys.argv[1], sys.argv[2]))
    else:
        c = bytes(range(TAM_HASH))
        p = bytes(range(TAM_HASH, 2 * TAM_HASH))
        interno = codificar_extensao(c, p)
        externo = codificar_extension_x509(c, p)
        print(f"SEQUENCE interna : {len(interno)} bytes")
        print(f"Extension X.509  : {len(externo)} bytes")
        print(f"OID              : {OID_INTENT}")
        print(f"ida e volta      : {decodificar_extensao(interno)[0] == VERSAO}")
