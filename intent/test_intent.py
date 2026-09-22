#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Testes de determinismo do coletor de intencao.

Rodar:  cd ~/ideia-pq/intent && python3 -m pytest test_intent.py -v

Estes testes existem porque o compromisso c so serve para alguma coisa se o
PEP conseguir recompor exatamente o mesmo valor a partir do contexto que
observa. Qualquer nao determinismo na canonizacao transforma uma propriedade
de seguranca em fonte de falso negativo.
"""

import hashlib
import json

import pytest

from intent import Intencao, de_evento, _canonizar, VERSAO_ESQUEMA


def base(**troca):
    campos = dict(
        r="unb/ideia-pq", b="refs/heads/main",
        dc="a" * 40, w="b" * 64, s="build",
        A=["push:registry/app", "read:cache"],
        t0=1_700_000_000, tau=30,
    )
    campos.update(troca)
    return Intencao(**campos)


# --------------------------------------------------------------- determinismo

def test_mesma_intencao_mesmo_compromisso():
    assert base().compromisso_hex() == base().compromisso_hex()


def test_ordem_de_A_nao_altera_o_compromisso():
    """A e conjunto, nao lista. Sem esta propriedade o PEP rejeitaria
    credencial legitima so porque o runner listou as acoes em outra ordem."""
    a = base(A=["read:cache", "push:registry/app"])
    b = base(A=["push:registry/app", "read:cache"])
    assert a.compromisso_hex() == b.compromisso_hex()


def test_compromisso_tem_48_bytes():
    """SHA-384. Se alguem trocar o hash sem atualizar o perfil ASN.1, a
    extensao muda de tamanho e os testes de seguranca pegam."""
    assert len(base().compromisso()) == 48
    assert len(base().compromisso_hex()) == 96


def test_canonico_nao_tem_espaco_supurfluo():
    c = base().canonico()
    assert b", " not in c and b": " not in c


def test_chaves_ordenadas():
    d = json.loads(base().canonico())
    assert list(d.keys()) == sorted(d.keys())


def test_versao_do_esquema_entra_no_hash():
    """A versao precisa ser coberta pelo compromisso: sem isso, uma mudanca de
    esquema de canonizacao passaria despercebida."""
    assert b'"v":%d' % VERSAO_ESQUEMA in base().canonico()


# ------------------------------------------------------------- sensibilidade

@pytest.mark.parametrize("campo,valor", [
    ("r", "outro/repo"),
    ("b", "refs/heads/feature"),
    ("dc", "c" * 40),
    ("w", "d" * 64),          # workflow trocado: o vetor de ataque da Secao IV-A
    ("s", "deploy"),
    ("t0", 1_700_000_001),
    ("tau", 31),
])
def test_qualquer_campo_altera_o_compromisso(campo, valor):
    assert base().compromisso_hex() != base(**{campo: valor}).compromisso_hex()


def test_acao_a_mais_altera_o_compromisso():
    a = base(A=["push:registry/app"])
    b = base(A=["push:registry/app", "delete:registry/app"])
    assert a.compromisso_hex() != b.compromisso_hex()


# -------------------------------------------------------------------- escopo

def test_cobre_apenas_acoes_declaradas():
    i = base(A=["push:registry/app"])
    assert i.cobre("push:registry/app")
    assert not i.cobre("delete:registry/app")


# --------------------------------------------------------------- construcao

def test_evento_incompleto_falha_alto():
    """Falhar cedo e ruidoso. Um evento sem workflow_digest produziria
    compromisso que nao protege contra substituicao de workflow."""
    with pytest.raises(ValueError) as e:
        de_evento({"repo": "x", "ref": "y", "commit": "z", "stage": "build"})
    assert "workflow_digest" in str(e.value)


def test_de_evento_equivale_a_construcao_direta():
    ev = {
        "repo": "unb/ideia-pq", "ref": "refs/heads/main",
        "commit": "a" * 40, "workflow_digest": "b" * 64, "stage": "build",
        "actions": ["push:registry/app", "read:cache"],
        "t0": 1_700_000_000, "tau": 30,
    }
    assert de_evento(ev).compromisso_hex() == base().compromisso_hex()


# ------------------------------------------------------- canonizacao (RFC 8785)

def test_canonizacao_ordena_por_code_point():
    assert _canonizar({"b": 1, "a": 2, "C": 3}) == b'{"C":3,"a":2,"b":1}'


def test_canonizacao_rejeita_nan():
    with pytest.raises(ValueError):
        _canonizar({"x": float("nan")})


def test_hash_bate_com_calculo_manual():
    """Ancora o valor: se a canonizacao mudar, este teste quebra e obriga a
    incrementar VERSAO_ESQUEMA."""
    i = base()
    esperado = hashlib.sha384(i.canonico()).hexdigest()
    assert i.compromisso_hex() == esperado
