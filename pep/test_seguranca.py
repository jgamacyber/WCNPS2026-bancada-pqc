#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Suite de seguranca do PEP: dez propriedades contra certificados REAIS.

Rodar:  cd ~/ideia-pq/pep && python3 -m pytest test_seguranca.py -v

Os certificados sao emitidos de verdade pela ACE, com extensao critica, e nao
simulados. Um teste que passa contra um objeto falso nao prova nada sobre o
caminho que roda em producao.

Sobre o teste_todas_as_rejeicoes_tem_o_motivo_certo: ele existe porque o
verificador falha fechado. Sem ele, uma excecao interna (arquivo faltando,
erro de digitacao no nome de campo) apareceria como 'rejeitado' e passaria por
propriedade de seguranca. Ja aconteceu neste projeto: dois testes passavam pelo
motivo errado porque o extrator devolvia lixo em silencio.
"""

import os
import subprocess
import sys
import time

import pytest

_AQUI = os.path.dirname(os.path.abspath(__file__))
_RAIZ = os.path.dirname(_AQUI)
for _p in (os.path.join(_RAIZ, "intent"), os.path.join(_RAIZ, "ace"), _AQUI):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from intent import Intencao                                     # noqa: E402
from extensao import codificar_extensao, TAM_HASH               # noqa: E402
import verificador as V                                         # noqa: E402

CA_DIR = os.path.join(_RAIZ, "ace", "ca", "EC")
EMITIR = os.path.join(_RAIZ, "ace", "emitir.sh")
POLITICA = bytes(range(TAM_HASH))          # resumo de politica fixo nos testes


# ------------------------------------------------------------------ fixtures

def _contexto(**troca):
    c = dict(
        r="unb/ideia-pq", b="refs/heads/main",
        dc="a" * 40, w="b" * 64, s="build",
        A=["push:registry/app", "read:cache"],
        t0=int(time.time()), tau=3600,
    )
    c.update(troca)
    return c


def _emitir(compromisso_hex, politica_hex, tau=3600, tmp=None):
    """Chama a ACE de verdade e devolve o DER do certificado emitido."""
    key = os.path.join(tmp, "leaf.key")
    csr = os.path.join(tmp, "leaf.csr")
    crt = os.path.join(tmp, "leaf.crt")
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-key", key, "-out", csr,
                    "-subj", "/CN=teste"], check=True, capture_output=True)
    r = subprocess.run(["bash", EMITIR, "EC", csr, compromisso_hex,
                        politica_hex, str(tau), crt],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail(f"a ACE falhou ao emitir: {r.stderr[-600:]}")
    der = subprocess.run(["openssl", "x509", "-in", crt, "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return der


@pytest.fixture(scope="module")
def ca_pem():
    p = os.path.join(CA_DIR, "ca.crt")
    if not os.path.isfile(p):
        pytest.skip(f"raiz da ACE ausente: {p}. Rode a Fase 7 do guia.")
    return p


@pytest.fixture
def cert_bom(tmp_path, ca_pem):
    ctx = _contexto()
    i = Intencao(**ctx)
    der = _emitir(i.compromisso_hex(), POLITICA.hex(), 3600, str(tmp_path))
    return der, ctx


# ============================================================ caminho feliz

def test_01_caminho_feliz_e_aceito(cert_bom, ca_pem):
    der, ctx = cert_bom
    ok, motivo = V.verificar(der, ctx, "push:registry/app", POLITICA, ca_pem)
    assert ok, f"o caminho feliz deveria passar, mas: {motivo}"


# ============================================================== rejeicoes

def test_02_uso_lateral_entre_estagios(cert_bom, ca_pem):
    """Credencial emitida para 'build' apresentada em 'deploy'."""
    der, ctx = cert_bom
    ok, motivo = V.verificar(der, _contexto(**{**ctx, "s": "deploy"}),
                             "push:registry/app", POLITICA, ca_pem)
    assert not ok
    assert "compromisso" in motivo


def test_03_substituicao_de_workflow(cert_bom, ca_pem):
    """O vetor classico: mesmo commit, definicao de pipeline trocada."""
    der, ctx = cert_bom
    ok, motivo = V.verificar(der, _contexto(**{**ctx, "w": "f" * 64}),
                             "push:registry/app", POLITICA, ca_pem)
    assert not ok
    assert "compromisso" in motivo


def test_04_commit_diferente(cert_bom, ca_pem):
    der, ctx = cert_bom
    ok, motivo = V.verificar(der, _contexto(**{**ctx, "dc": "e" * 40}),
                             "push:registry/app", POLITICA, ca_pem)
    assert not ok
    assert "compromisso" in motivo


def test_05_escopo_excedido(cert_bom, ca_pem):
    """Contexto integro, mas a operacao pedida nao esta em A."""
    der, ctx = cert_bom
    ok, motivo = V.verificar(der, ctx, "delete:registry/app", POLITICA, ca_pem)
    assert not ok
    assert "escopo" in motivo


def test_06_politica_divergente(cert_bom, ca_pem):
    der, ctx = cert_bom
    outra = bytes((b + 1) % 256 for b in POLITICA)
    ok, motivo = V.verificar(der, ctx, "push:registry/app", outra, ca_pem)
    assert not ok
    assert "olitica" in motivo


def test_07_extensao_ausente(tmp_path, ca_pem):
    """Certificado legitimo da mesma CA, porem sem a extensao de intencao."""
    key = tmp_path / "s.key"
    csr = tmp_path / "s.csr"
    crt = tmp_path / "s.crt"
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr),
                    "-subj", "/CN=sem-extensao"], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", str(csr),
                    "-CA", os.path.join(CA_DIR, "ca.crt"),
                    "-CAkey", os.path.join(CA_DIR, "ca.key"),
                    "-CAcreateserial", "-days", "1", "-out", str(crt)],
                   check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", str(crt), "-outform", "DER"],
                         check=True, capture_output=True).stdout
    ok, motivo = V.verificar(der, _contexto(), "push:registry/app",
                             POLITICA, ca_pem)
    assert not ok
    assert "ausente" in motivo


def test_08_certificado_expirado(tmp_path, ca_pem):
    """tau curto: espera passar da janela e confirma a rejeicao temporal."""
    ctx = _contexto(tau=1)
    i = Intencao(**ctx)
    der = _emitir(i.compromisso_hex(), POLITICA.hex(), 1, str(tmp_path))
    time.sleep(7)          # tau=1 mais a tolerancia de relogio delta=5 s
    ok, motivo = V.verificar(der, ctx, "push:registry/app", POLITICA, ca_pem)
    assert not ok
    assert "expirado" in motivo


def test_09_compromisso_adulterado(tmp_path, ca_pem):
    """A ACE assina um compromisso que nao corresponde a nenhuma intencao."""
    ctx = _contexto()
    falso = bytes((b ^ 0xFF) for b in Intencao(**ctx).compromisso())
    der = _emitir(falso.hex(), POLITICA.hex(), 3600, str(tmp_path))
    ok, motivo = V.verificar(der, ctx, "push:registry/app", POLITICA, ca_pem)
    assert not ok
    assert "compromisso" in motivo


def test_10_cadeia_de_outra_raiz(cert_bom, tmp_path):
    """Certificado bem formado, porem validado contra raiz que nao o emitiu."""
    der, ctx = cert_bom
    outra_ca = tmp_path / "outra.crt"
    outra_key = tmp_path / "outra.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
                    "-days", "1", "-subj", "/CN=outra-raiz",
                    "-keyout", str(outra_key), "-out", str(outra_ca)],
                   check=True, capture_output=True)
    ok, motivo = V.verificar(der, ctx, "push:registry/app",
                             POLITICA, str(outra_ca))
    assert not ok
    assert "cadeia" in motivo


# ================================================= guardas contra falso verde

def test_11_extensao_extraida_tem_114_bytes_e_e_critica(cert_bom):
    """Guarda contra o extrator devolver lixo em silencio.

    Sem esta checagem, um extrator quebrado faria os testes 02 a 04 passarem
    pelo motivo errado: qualquer valor diferente do esperado rejeita.
    """
    der, _ = cert_bom
    valor, critica = V.extrair_extensao_critica(der)
    assert len(valor) == 114, f"esperava 114 bytes, veio {len(valor)}"
    assert critica, "a extensao precisa estar marcada como critica"


def test_12_todas_as_rejeicoes_tem_o_motivo_certo(cert_bom, ca_pem, tmp_path):
    """Nenhuma rejeicao pode vir de excecao interna disfarcada."""
    der, ctx = cert_bom
    casos = [
        (_contexto(**{**ctx, "s": "deploy"}), "push:registry/app", POLITICA, "compromisso"),
        (_contexto(**{**ctx, "w": "f" * 64}), "push:registry/app", POLITICA, "compromisso"),
        (ctx, "delete:registry/app", POLITICA, "escopo"),
        (ctx, "push:registry/app", bytes(TAM_HASH), "olitica"),
    ]
    for contexto, op, pol, esperado in casos:
        ok, motivo = V.verificar(der, contexto, op, pol, ca_pem)
        assert not ok, f"deveria rejeitar: {contexto['s']}/{op}"
        assert "erro de verificacao" not in motivo, \
            f"rejeicao por excecao interna, nao por politica: {motivo}"
        assert esperado in motivo, \
            f"motivo errado: esperava '{esperado}', veio '{motivo}'"


def test_13_extensao_malformada_e_rejeitada_com_motivo_claro():
    """DER truncado nao pode virar aceitacao nem excecao nao tratada."""
    from extensao import decodificar_extensao, ErroExtensao
    bom = codificar_extensao(bytes(TAM_HASH), bytes(TAM_HASH))
    for corte in (1, 10, 50, len(bom) - 1):
        with pytest.raises(ErroExtensao):
            decodificar_extensao(bom[:corte])
