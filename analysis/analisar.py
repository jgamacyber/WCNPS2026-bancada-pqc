#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analisar.py - Fatorial 2x2, aditividade e decomposicao incremental.

O fatorial separa dois fatores que a literatura de PQ-TLS costuma mover juntos:
  A) o KEM         secp256r1  ->  SecP256r1MLKEM768
  B) a assinatura  ECDSA P-256 -> ML-DSA-44
Como o modo FIPS obrigou a usar secp256r1 no lugar do X25519, as duas celulas de
cada linha diferem SO pela adicao do ML-KEM sobre a mesma curva.

  C1 = (classico, ECDSA)   H1 = (hibrido, ECDSA)
  C3 = (classico, ML-DSA)  H2 = (hibrido, ML-DSA)
  P3 = pos-quantico puro (MLKEM768 + ML-DSA-65), fora do fatorial

Uso:
  python3 analisar.py --perfil lan --campo tempo --boot 10000
  python3 analisar.py --perfil lan --campo bytes
  python3 analisar.py --perfil wan --campo tempo
"""

import argparse, csv, glob, json, os, re, sys
import numpy as np

CONFIGS = {
    "C1": "secp256r1 + ECDSA P-256",
    "C3": "secp256r1 + ML-DSA-44",
    "H1": "SecP256r1MLKEM768 + ECDSA P-256",
    "H2": "SecP256r1MLKEM768 + ML-DSA-44",
    "P3": "MLKEM768 + ML-DSA-65",
}
ORDEM   = ["C1", "C3", "H1", "H2", "P3"]
CELULAS = ["C1", "C3", "H1", "H2"]

# Campos aceitos. Resolve-se olhando o primeiro registro em vez de adivinhar, e
# falha-se ruidosamente quando nenhum casa: numero silenciosamente errado e pior
# do que erro.
CAND = {"tempo":  ["ns"],
        "bytes":  ["bytes"],
        "voo_r":  ["bytes_r"],
        "voo_w":  ["bytes_w"]}
LIMIAR_PADRAO = 10 * 1448   # initcwnd do Linux vezes MSS com MTU 1500 e timestamps


def primeiro_registro(dados, perfil, modo):
    for f in sorted(glob.glob(f"{dados}/*_{perfil}_{modo}_*.jsonl")):
        for linha in open(f):
            try:
                return json.loads(linha)
            except json.JSONDecodeError:
                continue
    return None


def resolver(reg, campo):
    if reg is None:
        sys.exit("nenhum registro legivel encontrado")
    for k in CAND[campo]:
        if k in reg:
            div = 1000.0 if campo == "tempo" else 1.0
            return (lambda r, k=k, d=div: float(r[k]) / d), \
                   ("us" if campo == "tempo" else "bytes")
    sys.exit(f"campo {campo} ausente. chaves vistas: {sorted(reg)}")


def carregar(dados, cfg, perfil, modo, extrai):
    execucoes = []
    for f in sorted(glob.glob(f"{dados}/{cfg}_{perfil}_{modo}_*.jsonl"),
                    key=lambda p: int(re.search(r"_(\d+)\.jsonl$", p).group(1))):
        v = []
        for linha in open(f):
            try:
                v.append(extrai(json.loads(linha)))
            except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                pass
        if v:
            execucoes.append(np.asarray(v, dtype=float))
    return execucoes


def reamostra(execs, rng):
    """Bootstrap hierarquico: execucoes no nivel 1, operacoes no nivel 2.
    Achatar trataria 300 medicoes correlacionadas de um mesmo lote como 300
    observacoes independentes e estreitaria os intervalos artificialmente."""
    idx = rng.integers(0, len(execs), len(execs))
    return np.concatenate([execs[j][rng.integers(0, len(execs[j]), len(execs[j]))]
                           for j in idx])


def dec(x, c=2): return f"{x:.{c}f}".replace(".", "{,}")
def mil(x):      return f"{x:,.0f}".replace(",", "\\,")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dados", default="/dados/raw")
    ap.add_argument("--saida", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--perfil", default="lan")
    ap.add_argument("--modo", default="hs", choices=["hs", "emi", "ver"])
    ap.add_argument("--campo", default="tempo", choices=["tempo", "bytes"])
    ap.add_argument("--boot", type=int, default=10000)
    ap.add_argument("--semente", type=int, default=20260913)
    a = ap.parse_args()
    a.saida = os.path.abspath(a.saida); os.makedirs(a.saida, exist_ok=True)

    reg = primeiro_registro(a.dados, a.perfil, a.modo)
    extrai, unidade = resolver(reg, a.campo)
    print(f"\n=== {a.campo} de {a.modo}, perfil {a.perfil}, "
          f"{a.boot} reamostragens ({unidade}) ===")
    print(f"  chaves do registro: {sorted(reg)}")

    execs = {c: v for c in ORDEM
             if (v := carregar(a.dados, c, a.perfil, a.modo, extrai))}
    if not execs:
        sys.exit(f"nenhum dado em {a.dados} para modo={a.modo} perfil={a.perfil}")
    ausentes = [c for c in ORDEM if c not in execs]
    if ausentes:
        print(f"  sem dado: {', '.join(ausentes)}")

    rng   = np.random.default_rng(a.semente)
    ponto = {c: float(np.median(np.concatenate(execs[c]))) for c in execs}
    boot  = {c: np.empty(a.boot) for c in execs}
    for i in range(a.boot):
        for c in execs:
            boot[c][i] = np.median(reamostra(execs[c], rng))

    print(f"\n{'cfg':4s} {'configuracao':34s} {'exec':>4s} {'mediana':>12s} "
          f"{'IC 95%':>26s} {'vs C1':>7s}")
    base, linhas_tab, linhas_csv = ponto.get("C1"), [], []
    for cfg in ORDEM:
        if cfg not in execs: continue
        lo, hi = np.percentile(boot[cfg], [2.5, 97.5])
        rel = ponto[cfg] / base if base else float("nan")
        print(f"{cfg:4s} {CONFIGS[cfg]:34s} {len(execs[cfg]):4d} "
              f"{ponto[cfg]:12,.1f} [{lo:11,.1f}; {hi:11,.1f}] {rel:6.2f}x")
        linhas_tab.append(f"{cfg} & {CONFIGS[cfg]} & {mil(ponto[cfg])} & "
                          f"{dec(rel)} \\\\")
        linhas_csv.append(dict(cfg=cfg, descricao=CONFIGS[cfg],
                               n_execucoes=len(execs[cfg]),
                               n_operacoes=int(np.concatenate(execs[cfg]).size),
                               mediana=round(ponto[cfg], 2),
                               ic_lo=round(float(lo), 2), ic_hi=round(float(hi), 2),
                               razao_vs_C1=round(rel, 4), unidade=unidade))

    # ---------------------------------------------------------- aditividade
    # Os fatores se compoem por SOMA. Expressar os efeitos como razao produz uma
    # "interacao" que e artefato da parametrizacao, nao fenomeno.
    fatorial = {}
    if all(c in execs for c in CELULAS):
        d_kem = ponto["H2"] - ponto["C3"]
        d_sig = ponto["C3"] - ponto["C1"]
        prev  = ponto["C1"] + d_kem + d_sig
        resid = ponto["H2"] - prev
        total = ponto["H2"] - ponto["C1"]
        print(f"\n=== Aditividade (escala natural, {unidade}) ===")
        print(f"  efeito do KEM        {d_kem:+12,.1f}")
        print(f"  efeito da assinatura {d_sig:+12,.1f}   "
              f"({100.0*d_sig/total:.1f}% do acrescimo)")
        print(f"  H2 previsto          {prev:12,.1f}")
        print(f"  H2 observado         {ponto['H2']:12,.1f}")
        print(f"  residuo              {resid:+12,.1f}   "
              f"({100.0*resid/total:+.3f}% do acrescimo)")
        fatorial = dict(efeito_kem=round(d_kem, 2), efeito_sig=round(d_sig, 2),
                        previsto=round(prev, 2), observado=round(ponto["H2"], 2),
                        residuo=round(resid, 2),
                        residuo_pct=round(100.0 * resid / total, 4),
                        fracao_sig_pct=round(100.0 * d_sig / total, 2),
                        unidade=unidade)
    else:
        print(f"\n  fatorial incompleto: falta {[c for c in CELULAS if c not in execs]}")

    # ------------------------------------------------ decomposicao incremental
    caminho = [c for c in ("C1", "H1", "H2", "P3") if c in execs]
    incremental = []
    if len(caminho) >= 3:
        total = ponto[caminho[-1]] - ponto[caminho[0]]
        print(f"\n=== Decomposicao incremental ({' -> '.join(caminho)}) ===")
        print(f"    acrescimo total: {total:,.1f} {unidade} "
              f"({ponto[caminho[-1]]/ponto[caminho[0]]:.2f}x)")
        for i in range(len(caminho) - 1):
            de, para = caminho[i], caminho[i + 1]
            d = ponto[para] - ponto[de]
            frac = 100.0 * d / total if total else float("nan")
            print(f"  {de} -> {para}  {d:+12,.1f}  {frac:6.1f}%  ({CONFIGS[para]})")
            incremental.append(dict(de=de, para=para, delta=round(d, 2),
                                    fracao_pct=round(frac, 2)))

    # ------------------------------------------- voo por direcao e o limiar
    # E o voo de UM lado que precisa caber na primeira janela, nao o total.
    voos = {}
    if a.modo == "hs":
        er, _ = resolver(reg, "voo_r"); ew, _ = resolver(reg, "voo_w")
        print(f"\n=== Voo por direcao contra o limiar ({LIMIAR_PADRAO:,} bytes) ===")
        for cfg in ORDEM:
            if cfg not in execs: continue
            vr = carregar(a.dados, cfg, a.perfil, "hs", er)
            vw = carregar(a.dados, cfg, a.perfil, "hs", ew)
            if not vr: continue
            mr = float(np.median(np.concatenate(vr)))
            mw = float(np.median(np.concatenate(vw))) if vw else float("nan")
            seg = int(np.ceil(mr / 1448))
            marca = "  EXCEDE" if mr > LIMIAR_PADRAO else ""
            print(f"  {cfg:4s} servidor={mr:8,.0f}  cliente={mw:8,.0f}  "
                  f"({seg} segmentos){marca}")
            voos[cfg] = dict(servidor=mr, cliente=mw, segmentos=seg,
                             excede=bool(mr > LIMIAR_PADRAO))

    suf = f"{a.campo}_{a.perfil}"
    open(f"{a.saida}/tab_{suf}.tex", "w").write("\n".join(linhas_tab) + "\n")
    with open(f"{a.saida}/tab_{suf}.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(linhas_csv[0]))
        w.writeheader(); w.writerows(linhas_csv)
    json.dump(dict(perfil=a.perfil, modo=a.modo, campo=a.campo, unidade=unidade,
                   n_boot=a.boot, celulas=linhas_csv, aditividade=fatorial,
                   incremental=incremental, voos=voos, ausentes=ausentes),
              open(f"{a.saida}/tab_{suf}.json", "w"), indent=2)
    print(f"\nescrito em {a.saida}/: tab_{suf}.{{tex,csv,json}}")


if __name__ == "__main__":
    main()
