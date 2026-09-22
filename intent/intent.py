#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Coletor de Intencao do IDEIA-PQ.

Deriva a declaracao canonica de intencao a partir do evento que dispara o
pipeline e produz o compromisso c = H(enc(I)), com H = SHA-384.

A canonizacao segue as regras do RFC 8785 (JSON Canonicalization Scheme):
chaves ordenadas pela representacao UTF-16, separadores sem espaco, UTF-8 na
saida. O escopo usado aqui e um subconjunto do JCS: todos os valores sao
strings, inteiros ou listas de strings, entao a serializacao numerica do
ECMAScript nao chega a ser exercitada. Isso esta declarado de proposito, para
que ninguem assuma conformidade total com o RFC.

ATENCAO: este arquivo e escrito por 'tar -xzf', nunca por copiar e colar.
Comandos de shell colados aqui por engano quebram tudo em silencio, que foi
exatamente o que aconteceu na primeira tentativa de bancada.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import List

VERSAO_ESQUEMA = 1
HASH = "sha384"


def _canonizar(obj) -> bytes:
    """Serializacao canonica, subconjunto do RFC 8785.

    sort_keys ordena por code point Unicode. Para as chaves usadas aqui, que
    sao todas ASCII minusculo, isso coincide com a ordenacao por unidade de
    codigo UTF-16 exigida pelo JCS. Se algum dia aparecer chave fora do plano
    basico multilingue, esta funcao precisa ser revista.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class Intencao:
    """A tupla I da Equacao (1) do artigo.

    r   repositorio
    b   referencia de codigo (branch, tag)
    dc  resumo do commit
    w   resumo da definicao de workflow EFETIVAMENTE carregada
    s   identificador do estagio
    A   conjunto de acoes pretendidas sobre alvos nomeados
    t0  instante de emissao, epoch em segundos
    tau validade solicitada, em segundos
    """

    r: str
    b: str
    dc: str
    w: str
    s: str
    A: List[str] = field(default_factory=list)
    t0: int = 0
    tau: int = 0

    def como_dicionario(self) -> dict:
        # O conjunto A e ordenado antes de serializar. Sem isso, duas
        # invocacoes com as mesmas acoes em ordem diferente produziriam
        # compromissos distintos, e o PEP rejeitaria credencial legitima.
        return {
            "v": VERSAO_ESQUEMA,
            "r": self.r,
            "b": self.b,
            "dc": self.dc,
            "w": self.w,
            "s": self.s,
            "A": sorted(self.A),
            "t0": int(self.t0),
            "tau": int(self.tau),
        }

    def canonico(self) -> bytes:
        return _canonizar(self.como_dicionario())

    def compromisso(self) -> bytes:
        return hashlib.new(HASH, self.canonico()).digest()

    def compromisso_hex(self) -> str:
        return self.compromisso().hex()

    def cobre(self, acao: str) -> bool:
        """A operacao requisitada pertence ao conjunto A declarado?"""
        return acao in self.A


def de_evento(evento: dict) -> Intencao:
    """Constroi a intencao a partir do evento do sistema de controle de versao.

    O evento e a FONTE AUTORITATIVA. Este coletor roda fora do runner, e a
    Secao IV-C do artigo declara que um coletor comprometido produz credencial
    valida para intencao maliciosa: a assinatura protege a integridade depois
    da emissao, nao a veracidade antes dela.
    """
    faltando = [k for k in ("repo", "ref", "commit", "workflow_digest", "stage")
                if not evento.get(k)]
    if faltando:
        raise ValueError(f"evento incompleto, faltam: {', '.join(faltando)}")

    return Intencao(
        r=str(evento["repo"]),
        b=str(evento["ref"]),
        dc=str(evento["commit"]),
        w=str(evento["workflow_digest"]),
        s=str(evento["stage"]),
        A=list(evento.get("actions", [])),
        t0=int(evento.get("t0", 0)),
        tau=int(evento.get("tau", 0)),
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--exemplo":
        i = Intencao(
            r="unb/ideia-pq", b="refs/heads/main",
            dc="a" * 40, w="b" * 64, s="build",
            A=["push:registry/app", "read:cache"],
            t0=1_700_000_000, tau=30,
        )
        print("canonico:", i.canonico().decode())
        print("compromisso:", i.compromisso_hex())
        sys.exit(0)

    # Sem argumento: le o evento em JSON da entrada padrao e imprime o
    # compromisso em hexadecimal. E assim que o emitir.sh o invoca.
    print(de_evento(json.load(sys.stdin)).compromisso_hex())
