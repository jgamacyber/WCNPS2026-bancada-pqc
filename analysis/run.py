#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Orquestrador da bancada IDEIA-PQ.

Randomiza a ordem de TODOS os tratamentos, que e a mitigacao direta do vies de
medicao descrito por Mytkowicz et al.

Uso:
  python3 run.py --perfil lan --dry-run       # valida ambiente e estima duracao
  sudo python3 run.py --perfil lan --reps 2   # ensaio curto, confere que roda
  sudo python3 run.py --perfil lan            # campanha completa, 30 execucoes

Saida: /dados/raw/<CFG>_<perfil>_<modo>_<rep>.jsonl
       /dados/raw/sessao_<perfil>.json

CORRECOES EM RELACAO A PRIMEIRA CAMPANHA, que perdeu 196 de 210 lotes:
  1. Servidor no nucleo 0, cliente no nucleo 1 isolado. Antes os dois
     disputavam o nucleo 1, serializavam, e o lote estourava o tempo limite.
  2. pkill do servidor orfao ANTES de cada lote, nao so depois de falha. Um
     servidor sobrevivente segurava a porta 4443 com SO_REUSEADDR e travava
     o lote seguinte.
  3. Certificados sao reemitidos quando faltam menos de 3 h de validade, em vez
     de reaproveitados indefinidamente.
  4. Tempo limite de 300 s por lote, e N por lote reduzido: 300 handshakes em
     vez de 1000. Trezentos ja dao percentil 95 estavel e o lote termina em
     segundos, nao em minutos.
"""

import argparse
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import time

# Resolve a raiz pelo proprio arquivo: sob sudo, HOME vira /root e
# expanduser("~") apontaria para o lugar errado.
R       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DADOS   = "/dados/raw"
PKI     = "/dados/pki"
LOG     = "/dados/execucao.log"
SEMENTE = 20260913
BENCH   = f"{R}/bench/bench"
PAUSA   = 8            # pausa termica entre lotes, chassi de 15 W sem ventoinha
TAU_PKI = 21600        # 6 h de validade dos certificados da bancada
LIMITE  = 300          # tempo limite por lote, em segundos

# -----------------------------------------------------------------------------
# Configuracoes.
#
# O nucleo do desenho e o fatorial 2x2 completo, que a primeira campanha nao
# tinha e que o parecer cobrou (item M-04):
#
#                      | autenticacao classica | autenticacao PQ
#   ---------------------------------------------------------------
#   troca classica     | C1                    | C3   <-- a celula que faltava
#   troca hibrida      | H1                    | H2
#
# Com as quatro celulas da para estimar o efeito principal de cada fator E a
# interacao entre eles. Sem C3, os 89,4% ficam presos ao caminho C1->H1->H2.
#
# P3 e P5 sao pontos adicionais: P3 e puramente pos-quantica e P5 e o CONTROLE
# da hipotese da cauda, por ser caro e ao mesmo tempo regular (SLH-DSA nao tem
# laco de rejeicao).
# -----------------------------------------------------------------------------
CONFIGS = {
    "C1": dict(alg="EC:P-256",          grupo="secp256r1",         sigalg=None,      extra=False),
    "C3": dict(alg="ML-DSA-44",         grupo="secp256r1",         sigalg="mldsa44", extra=False),
    "H1": dict(alg="EC:P-256",          grupo="SecP256r1MLKEM768", sigalg=None,      extra=False),
    "H2": dict(alg="ML-DSA-44",         grupo="SecP256r1MLKEM768", sigalg="mldsa44", extra=False),
    "P3": dict(alg="ML-DSA-65",         grupo="MLKEM768",          sigalg="mldsa65", extra=False),
    # O modo FIPS retira o X25519 dos grupos disponiveis, o que forcou secp256r1
    # e, sem querer, melhorou o desenho: C1 e H1 passam a diferir SO pelo
    # acrescimo do ML-KEM sobre a mesma curva.
    #
    # SLH-DSA nao negocia handshake TLS 1.3 por ausencia de code point de
    # SignatureScheme, e RSA:3072 leva ~800 ms so na geracao de chave. Ambos
    # ficam de fora da campanha de handshake.
    "P5": dict(alg="SLH-DSA-SHA2-128f", grupo="MLKEM768",          sigalg=None,      extra=True),
    "C2": dict(alg="RSA:3072",          grupo="secp256r1",         sigalg=None,      extra=True),
}

# Operacoes por lote. Dimensionadas para o lote fechar em segundos no i3-4005U.
# Trinta execucoes independentes de 300 handshakes dao 9000 observacoes por
# configuracao, o suficiente para p95 estavel. Percentil 99 confiavel exigiria
# mais, e o artigo declara essa limitacao em vez de fingir que nao existe.
N_EMI = {"C1": 500, "C3": 500, "H1": 500, "H2": 500, "P3": 500, "P5":  60, "C2": 100}
N_HS  = {"C1": 300, "C3": 300, "H1": 300, "H2": 300, "P3": 300, "P5":  30, "C2":  50}
W_EMI, W_HS = 50, 20

# Custo por operacao em microssegundos, do piloto. So serve para estimar
# duracao no --dry-run; nenhum resultado depende destes numeros.
CUSTO = {
    "C1": dict(emi=262,    ver=204, hs=3224),
    "C3": dict(emi=1644,   ver=324, hs=6500),
    "H1": dict(emi=262,    ver=204, hs=3676),
    "H2": dict(emi=1644,   ver=324, hs=7372),
    "P3": dict(emi=2646,   ver=489, hs=9168),
    "P5": dict(emi=110000, ver=400, hs=40000),
    "C2": dict(emi=800000, ver=250, hs=6000),
}


# ----------------------------------------------------------------- utilidades

def log(msg):
    linha = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(linha, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(linha + "\n")
    except OSError:
        pass


def throttle():
    total = 0
    achou = False
    for cpu in (0, 1):
        p = f"/sys/devices/system/cpu/cpu{cpu}/thermal_throttle/core_throttle_count"
        try:
            total += int(open(p).read().strip())
            achou = True
        except (OSError, ValueError):
            pass
    return str(total) if achou else "n/a"


def freq_mhz():
    try:
        for l in open("/proc/cpuinfo"):
            if "MHz" in l:
                return float(l.split(":")[1])
    except OSError:
        pass
    return 0.0


def matar_orfaos():
    """Servidor sobrevivente de um lote anterior segura a porta 4443.

    Com SO_REUSEADDR o bind seguinte nao falha: ele fica pendurado, e so o
    tempo limite percebe. Este pkill e a correcao mais importante do arquivo.
    """
    subprocess.run(["pkill", "-9", "-f", "bench --mode hs-server"],
                   capture_output=True)
    time.sleep(0.3)


def suportado(cfg):
    c = CONFIGS[cfg]
    alg = c["alg"].split(":")[0]
    gen = ["openssl", "genpkey"]
    if alg == "EC":
        gen += ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
    elif alg == "RSA":
        gen += ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]
    else:
        gen += ["-algorithm", c["alg"]]
    if subprocess.run(gen + ["-out", "/dev/null"],
                      capture_output=True).returncode != 0:
        return False, f"algoritmo {c['alg']} indisponivel"
    saida = subprocess.run(["openssl", "list", "-tls-groups"],
                           capture_output=True, text=True).stdout.lower()
    # Pertinencia exata, nao substring: "x25519" casaria dentro de
    # "x25519mlkem768" e daria o grupo por disponivel quando nao esta.
    grupos = {l.strip().lstrip("- ").split()[0] for l in saida.splitlines() if l.strip()}
    if c["grupo"].lower() not in grupos:
        return False, f"grupo TLS {c['grupo']} indisponivel"
    return True, "ok"


# ----------------------------------------------------------------------- PKI

def nome_ca(cfg):
    alg = CONFIGS[cfg]["alg"]
    return alg.split(":")[0] if alg.startswith(("EC", "RSA")) else alg


def cert_valido(caminho, folga=10800):
    """Sobra pelo menos 'folga' segundos de validade?"""
    if not os.path.isfile(caminho):
        return False
    r = subprocess.run(["openssl", "x509", "-in", caminho, "-noout",
                        "-checkend", str(folga)], capture_output=True)
    return r.returncode == 0


def preparar_pki(cfg):
    """Garante raiz e par de entidade final validos para a configuracao.

    Reemite quando falta menos de 3 h. Na primeira campanha os certificados
    eram reaproveitados sem checagem e venceram no meio da sessao, o que
    sozinho explicou a maioria das falhas.
    """
    c = CONFIGS[cfg]
    ca_dir = f"{R}/ace/ca/{nome_ca(cfg)}"
    subprocess.run(["bash", f"{R}/ace/init-ca.sh", nome_ca(cfg)],
                   check=True, capture_output=True)

    crt, key = f"{PKI}/{cfg}.crt", f"{PKI}/{cfg}.key"
    if cert_valido(crt) and os.path.isfile(key):
        return ca_dir, crt, key

    os.makedirs(PKI, exist_ok=True)
    gen = ["openssl", "genpkey"]
    if c["alg"].startswith("EC"):
        curva = c["alg"].split(":")[1] if ":" in c["alg"] else "P-256"
        gen += ["-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curva}"]
    elif c["alg"].startswith("RSA"):
        bits = c["alg"].split(":")[1] if ":" in c["alg"] else "3072"
        gen += ["-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}"]
    else:
        gen += ["-algorithm", c["alg"]]
    subprocess.run(gen + ["-out", key], check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-key", key,
                    "-out", f"/tmp/{cfg}.csr", "-subj", f"/CN={cfg}"],
                   check=True, capture_output=True)

    env = dict(os.environ, PYTHONPATH=f"{R}/intent:{R}/ace")
    compromisso = subprocess.run(
        ["python3", "-c",
         "from intent import Intencao;"
         "print(Intencao('bancada','main','c'*40,'w'*64,'build',"
         "['push:registry/app'],0,%d).compromisso_hex())" % TAU_PKI],
        capture_output=True, text=True, check=True, env=env).stdout.strip()
    politica = subprocess.run(["openssl", "rand", "-hex", "48"],
                              capture_output=True, text=True,
                              check=True).stdout.strip()
    subprocess.run(["bash", f"{R}/ace/emitir.sh", nome_ca(cfg),
                    f"/tmp/{cfg}.csr", compromisso, politica,
                    str(TAU_PKI), crt], check=True, capture_output=True)
    return ca_dir, crt, key


# ------------------------------------------------------------------ execucao

def rodar(cfg, perfil, rep, modos):
    c = CONFIGS[cfg]
    ca_dir, crt, key = preparar_pki(cfg)
    ca, cak = f"{ca_dir}/ca.crt", f"{ca_dir}/ca.key"

    if "emi" in modos:
        subprocess.run(
            ["taskset", "-c", "1", BENCH, "--mode", "emi", "--alg", c["alg"],
             "--ca-crt", ca, "--ca-key", cak,
             "--n", str(N_EMI[cfg]), "--warmup", str(W_EMI),
             "--out", f"{DADOS}/{cfg}_{perfil}_emi_{rep}.jsonl"],
            check=True, timeout=LIMITE, stderr=subprocess.DEVNULL)

    if "ver" in modos:
        subprocess.run(
            ["taskset", "-c", "1", BENCH, "--mode", "ver",
             "--leaf", crt, "--ca-crt", ca,
             "--n", str(N_EMI[cfg]), "--warmup", str(W_EMI),
             "--out", f"{DADOS}/{cfg}_{perfil}_ver_{rep}.jsonl"],
            check=True, timeout=LIMITE, stderr=subprocess.DEVNULL)

    if "hs" in modos:
        matar_orfaos()

        # Servidor no nucleo 0, cliente no nucleo 1 (isolado por isolcpus).
        # Na primeira campanha os dois iam para o nucleo 1 e serializavam, o
        # que estourava o tempo limite. Consequencia a declarar no artigo:
        # T_hs passa a ser medido com os dois lados em nucleos distintos, e nao
        # e mais uma medida serializada.
        base_srv = ["ip", "netns", "exec", "ci-server", "taskset", "-c", "0",
                    BENCH, "--mode", "hs-server", "--ip", "10.99.0.2",
                    "--porta", "4443", "--crt", crt, "--key", key,
                    "--ca-crt", ca, "--grupos", c["grupo"],
                    "--n", str(N_HS[cfg]), "--warmup", str(W_HS)]
        base_cli = ["ip", "netns", "exec", "ci-client", "taskset", "-c", "1",
                    BENCH, "--mode", "hs-client", "--ip", "10.99.0.2",
                    "--porta", "4443", "--crt", crt, "--key", key,
                    "--ca-crt", ca, "--grupos", c["grupo"],
                    "--n", str(N_HS[cfg]), "--warmup", str(W_HS),
                    "--out", f"{DADOS}/{cfg}_{perfil}_hs_{rep}.jsonl"]
        if c["sigalg"]:
            base_srv += ["--sigalgs", c["sigalg"]]
            base_cli += ["--sigalgs", c["sigalg"]]

        p = subprocess.Popen(base_srv, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        if p.poll() is not None:
            raise RuntimeError(f"servidor morreu antes do cliente conectar "
                               f"(codigo {p.returncode})")
        try:
            subprocess.run(base_cli, check=True, timeout=LIMITE,
                           stderr=subprocess.DEVNULL)
        finally:
            try:
                p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
            matar_orfaos()


def estimar(configs, reps, modos):
    total = 0.0
    for cfg in configs:
        c, seg = CUSTO[cfg], 0.0
        if "emi" in modos: seg += (N_EMI[cfg] + W_EMI) * c["emi"] / 1e6
        if "ver" in modos: seg += (N_EMI[cfg] + W_EMI) * c["ver"] / 1e6
        if "hs"  in modos: seg += (N_HS[cfg] + W_HS) * c["hs"] / 1e6 + 1.5
        total += reps * (seg + PAUSA)
    return total


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--perfil", required=True, choices=["lan", "dc", "wan"])
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--modos", default="emi,ver,hs")
    ap.add_argument("--configs", default="C1,C3,H1,H2,P3,P5",
                    help="lista separada por virgula, ou 'todas'")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    modos = a.modos.split(",")
    pedidas = list(CONFIGS) if a.configs == "todas" else a.configs.split(",")
    for c in pedidas:
        if c not in CONFIGS:
            sys.exit(f"configuracao desconhecida: {c}")

    print("=== Ambiente ===")
    problemas = []
    if os.path.isfile(BENCH) and os.access(BENCH, os.X_OK):
        # test -f e nao test -x sobre o diretorio: 'bench/' tambem e executavel
        # e a checagem antiga mentia quando o binario nao existia.
        print(f"  OK    harness: {BENCH}")
    else:
        problemas.append(f"binario ausente: {BENCH} (rode a Fase 5 do guia)")
    if shutil.which("ip") is None:
        problemas.append("comando 'ip' ausente")
    else:
        ns = subprocess.run(["ip", "netns", "list"],
                            capture_output=True, text=True).stdout
        for n in ("ci-client", "ci-server"):
            if n in ns:
                print(f"  OK    namespace {n}")
            else:
                problemas.append(f"namespace {n} ausente (sudo bash scripts/rede.sh criar)")
    f = freq_mhz()
    print(f"  {'OK   ' if f > 1650 else 'AVISO'} frequencia {f:.0f} MHz")
    print(f"  --    throttle acumulado: {throttle()}")
    n_cpus = os.cpu_count() or 1
    if n_cpus < 2:
        problemas.append("a bancada precisa de 2 nucleos: servidor no 0, cliente no 1")
    if os.geteuid() != 0 and not a.dry_run:
        problemas.append("execute com sudo: 'ip netns exec' exige privilegio")

    print("\n=== Configuracoes ===")
    validas = []
    for cfg in pedidas:
        ok, motivo = suportado(cfg)
        marca = "OK  " if ok else ("PULA" if CONFIGS[cfg]["extra"] else "ERRO")
        print(f"  {marca} {cfg:3s} {CONFIGS[cfg]['alg']:20s} "
              f"{CONFIGS[cfg]['grupo']:18s} {motivo}")
        if ok:
            validas.append(cfg)
        elif not CONFIGS[cfg]["extra"]:
            problemas.append(f"{cfg} e obrigatoria e indisponivel: {motivo}")

    faltando_2x2 = [c for c in ("C1", "C3", "H1", "H2") if c not in validas]
    if faltando_2x2:
        print(f"\n  AVISO: o fatorial 2x2 fica incompleto sem {faltando_2x2}.")
        print("         A interacao entre troca de chaves e autenticacao nao")
        print("         sera estimavel, e os percentuais da decomposicao")
        print("         continuam presos ao caminho medido.")

    if problemas:
        print("\n=== PROBLEMAS ===")
        for p in problemas:
            print(f"  {p}")
        sys.exit(1)

    plano = list(itertools.product(validas, range(a.reps)))
    random.seed(SEMENTE)
    random.shuffle(plano)

    seg = estimar(validas, a.reps, modos)
    print("\n=== Plano ===")
    print(f"  perfil       : {a.perfil}")
    print(f"  configuracoes: {', '.join(validas)}")
    print(f"  modos        : {', '.join(modos)}")
    print(f"  execucoes    : {a.reps} por configuracao")
    print(f"  lotes        : {len(plano)}")
    print(f"  semente      : {SEMENTE}")
    print(f"  duracao est. : {seg/60:.0f} min ({seg/3600:.1f} h)")
    print(f"  ordem inicial: {' '.join(f'{c}#{r}' for c, r in plano[:8])} ...")

    if a.dry_run:
        print("\n(dry-run: nenhuma medicao foi feita)")
        return

    os.makedirs(DADOS, exist_ok=True)
    subprocess.run(["bash", f"{R}/scripts/rede.sh", "perfil", a.perfil],
                   check=True)

    t_ini = throttle()
    log(f"INICIO perfil={a.perfil} configs={validas} reps={a.reps} throttle={t_ini}")

    falhas, t0 = [], time.time()
    for i, (cfg, rep) in enumerate(plano, 1):
        resta = (time.time() - t0) / (i - 1) * (len(plano) - i + 1) if i > 1 else seg
        log(f"[{i}/{len(plano)}] {cfg} rep={rep}  (resta ~{resta/60:.0f} min)")
        try:
            rodar(cfg, a.perfil, rep, modos)
        except Exception as e:                      # noqa: BLE001
            falhas.append([cfg, rep, f"{type(e).__name__}: {e}"])
            log(f"    FALHOU: {type(e).__name__}: {e}")
            matar_orfaos()
            # Aborta se as falhas viraram regra: melhor parar em 10 minutos do
            # que descobrir 7 horas depois que a sessao inteira se perdeu.
            if len(falhas) >= 10 and len(falhas) > i * 0.5:
                log("ABORTANDO: mais da metade dos lotes falhou. "
                    "Confira o log antes de continuar.")
                break
        time.sleep(PAUSA)

    t_fim = throttle()
    log(f"FIM throttle={t_ini} -> {t_fim}  falhas={len(falhas)}")

    with open(f"{DADOS}/sessao_{a.perfil}.json", "w") as fh:
        json.dump(dict(perfil=a.perfil, configs=validas, reps=a.reps,
                       modos=modos, semente=SEMENTE, throttle_antes=t_ini,
                       throttle_depois=t_fim, falhas=falhas,
                       duracao_s=round(time.time() - t0),
                       n_emi=N_EMI, n_hs=N_HS,
                       warmup_emi=W_EMI, warmup_hs=W_HS), fh, indent=2)

    print()
    if t_fim != t_ini:
        print("ATENCAO: houve throttling termico. DESCARTE esta sessao.",
              file=sys.stderr)
        sys.exit(1)
    if falhas:
        print(f"Sessao concluida com {len(falhas)} falha(s) de {len(plano)}. "
              f"Veja {LOG}.")
        sys.exit(2)
    print(f"Sessao concluida sem falhas em {(time.time()-t0)/60:.0f} min.")
    print(f"Metadados: {DADOS}/sessao_{a.perfil}.json")


if __name__ == "__main__":
    main()
