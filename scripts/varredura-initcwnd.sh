#!/usr/bin/env bash
# =============================================================================
#  varredura-initcwnd.sh - Curva dose-resposta do degrau de congestionamento
#
#  Mede a mesma configuracao TLS variando SO a janela inicial de congestionamento.
#  Se o degrau relatado no artigo for mesmo causado por initcwnd, a latencia nao
#  cai de forma gradual: ela desaba nos pontos em que a janela passa a acomodar
#  os voos, e fica plana depois.
#
#  PREVISAO REGISTRADA ANTES DA MEDICAO (artigo, Tabela III): degrau unico entre
#  10 e 11 segmentos. O observado foram DOIS degraus, com plato em 12, por dois
#  motivos: o MSS efetivo e 1448 e nao 1460 (opcao de timestamps), e em mTLS
#  cada lado envia seu proprio voo, de modo que o criterio incide duas vezes.
#
#  Uso:  sudo bash scripts/varredura-initcwnd.sh [CFG]   (CFG padrao: P3)
# =============================================================================
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${1:-P3}"
SAIDA="/dados/varredura_initcwnd_${CFG}.csv"
JANELAS="10 11 12 13 14 20 40"
REPS=3

[[ $EUID -eq 0 ]] || { echo "precisa de root: use sudo"; exit 1; }
pgrep -f "run.py" >/dev/null && { echo "bancada ocupada"; exit 1; }
[[ -f "/dados/pki/${CFG}.crt" ]] || {
  echo "falta /dados/pki/${CFG}.crt. Os certificados valem 6 h; reemita com:"
  echo "  sudo python3 analysis/run.py --perfil wan --modos hs --configs ${CFG} --reps 1"
  exit 1; }

case "$CFG" in
  P3) CA="$R/ace/ca/ML-DSA-65/ca.crt"; GRUPO=MLKEM768;          SIG=mldsa65 ;;
  H2) CA="$R/ace/ca/ML-DSA-44/ca.crt"; GRUPO=SecP256r1MLKEM768; SIG=mldsa44 ;;
  C1) CA="$R/ace/ca/EC/ca.crt";        GRUPO=secp256r1;         SIG="" ;;
  *) echo "configuracao nao prevista: $CFG"; exit 1 ;;
esac
SIGOPT=(); [[ -n "$SIG" ]] && SIGOPT=(--sigalgs "$SIG")

ajustar () {
  for ns in ci-server ci-client; do
    d=$(ip netns exec "$ns" ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v '^lo$' | head -1)
    p=$(ip netns exec "$ns" ip -o -4 route show dev "$d" scope link | awk '{print $1}' | head -1)
    ip netns exec "$ns" ip route change "$p" dev "$d" initcwnd "$1" initrwnd "$1"
  done
}

medir () {   # $1 = initcwnd, $2 = repeticao
  # pkill por NOME do executavel, nao por linha de comando: com -f o padrao
  # casaria a propria linha deste script quando ele e colado inline, e o
  # processo se mataria.
  pkill -9 -x bench 2>/dev/null || true; sleep 1
  ip netns exec ci-server taskset -c 0 "$R/bench/bench" --mode hs-server \
    --ip 10.99.0.2 --porta 4443 --crt "/dados/pki/${CFG}.crt" \
    --key "/dados/pki/${CFG}.key" --ca-crt "$CA" --grupos "$GRUPO" \
    "${SIGOPT[@]}" --n 120 --warmup 20 2>/dev/null &
  sleep 1
  ip netns exec ci-client taskset -c 1 "$R/bench/bench" --mode hs-client \
    --ip 10.99.0.2 --porta 4443 --crt "/dados/pki/${CFG}.crt" \
    --key "/dados/pki/${CFG}.key" --ca-crt "$CA" --grupos "$GRUPO" \
    "${SIGOPT[@]}" --n 120 --warmup 20 --out "/tmp/sw_$1_$2.jsonl" 2>/dev/null
  python3 -c "
import json, statistics
v=[json.loads(l)['ns']/1000 for l in open('/tmp/sw_$1_$2.jsonl') if l.strip()]
b=[json.loads(l).get('bytes_r',0) for l in open('/tmp/sw_$1_$2.jsonl') if l.strip()]
print('$1,%d,$2,%.1f,%.0f' % ($1*1448, statistics.median(v), statistics.median(b)))" >> "$SAIDA"
}

bash "$R/scripts/rede.sh" perfil wan
echo "initcwnd,janela_bytes_mss1448,rep,mediana_us,voo_servidor_bytes" > "$SAIDA"
echo
for w in $JANELAS; do
  ajustar "$w"
  for r in $(seq 0 $((REPS-1))); do medir "$w" "$r"; done
  printf "  initcwnd=%-3s janela=%-6s  medianas: %s us\n" \
         "$w" "$((w*1448))" "$(tail -$REPS "$SAIDA" | cut -d, -f4 | tr '\n' ' ')"
done

# Restaurar e obrigatorio: um initcwnd esquecido corrompe em silencio qualquer
# campanha posterior.
ajustar 10
echo
echo "janela restaurada para 10. resultado em $SAIDA"
column -s, -t "$SAIDA"
