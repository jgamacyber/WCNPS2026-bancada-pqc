#!/usr/bin/env bash
# =============================================================================
#  rede.sh - Namespaces de rede e perfis de enlace
#
#    sudo bash rede.sh criar          cria ci-client e ci-server com par veth
#    sudo bash rede.sh perfil lan     enlace local, sem emulacao
#    sudo bash rede.sh perfil dc      RTT 1 ms, sem perda
#    sudo bash rede.sh perfil wan     RTT 40 ms, perda 0,5%
#    sudo bash rede.sh estado         mostra a configuracao atual
#    sudo bash rede.sh destruir       remove tudo
#
#  O nome da interface e DESCOBERTO dentro do namespace, e o perfil e VERIFICADO
#  por ping depois de aplicado. Uma versao anterior assumia 'veth-cli' e
#  'veth-srv'; quando os nomes eram outros o tc falhava, o enlace ficava sem
#  atraso e uma campanha inteira rodou com rotulo wan e enlace lan. Um passo que
#  falha em silencio e pior do que um passo ausente.
# =============================================================================
set -euo pipefail
export LC_ALL=C

CLI=ci-client; SRV=ci-server
IP_CLI=10.99.0.1; IP_SRV=10.99.0.2; MASCARA=30

erro() { echo "rede.sh: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || erro "precisa de root: use sudo"

# Primeira interface que nao seja loopback. O sufixo @ifNN do peer sai fora.
dev_de() {
    local ns="$1" d
    d=$(ip netns exec "$ns" ip -o link show 2>/dev/null \
        | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v '^lo$' | head -1)
    [[ -n "$d" ]] || erro "namespace ${ns} nao tem interface de rede"
    printf '%s' "$d"
}

rtt_ms() {
    ip netns exec "$CLI" ping -c 5 -i 0.2 -W 2 -q "$IP_SRV" 2>/dev/null \
        | awk -F'/' '/min\/avg/ {print $5}'
}

criar() {
    destruir 2>/dev/null || true
    ip netns add "$CLI"; ip netns add "$SRV"
    ip link add veth-cli type veth peer name veth-srv
    ip link set veth-cli netns "$CLI"; ip link set veth-srv netns "$SRV"
    ip -n "$CLI" addr add "${IP_CLI}/${MASCARA}" dev veth-cli
    ip -n "$SRV" addr add "${IP_SRV}/${MASCARA}" dev veth-srv
    ip -n "$CLI" link set veth-cli up; ip -n "$SRV" link set veth-srv up
    ip -n "$CLI" link set lo up;       ip -n "$SRV" link set lo up

    # Com TSO/GSO/GRO ligados o nucleo agrega segmentos, a contagem de bytes no
    # socket deixa de refletir o que a rede veria, e a agregacao mascara o
    # efeito de tamanho que a campanha existe para medir.
    for ns in "$CLI" "$SRV"; do
        d=$(dev_de "$ns")
        ip netns exec "$ns" ethtool -K "$d" \
            tso off gso off gro off lro off tx off rx off 2>/dev/null || true
        ip netns exec "$ns" ip link set "$d" mtu 1500
    done
    echo "namespaces criados: ${CLI} (${IP_CLI}) <-> ${SRV} (${IP_SRV})"
    perfil lan
}

limpar_qdisc() {
    for ns in "$CLI" "$SRV"; do
        d=$(dev_de "$ns")
        ip netns exec "$ns" tc qdisc del dev "$d" root 2>/dev/null || true
    done
}

perfil() {
    local nome="${1:-lan}" DELAY="" PERDA="" alvo=0
    ip netns list | grep -q "$CLI" || erro "namespaces ausentes: rode 'rede.sh criar'"
    limpar_qdisc
    # netem aplica o atraso em CADA sentido: metade do RTT alvo por lado.
    case "$nome" in
        lan) alvo=0 ;;
        dc)  DELAY="delay 0.5ms 0.1ms distribution normal"; alvo=1  ;;
        wan) DELAY="delay 20ms 2ms distribution normal"; PERDA="loss 0.5%"; alvo=40 ;;
        *)   erro "perfil desconhecido: $nome (use lan, dc ou wan)" ;;
    esac

    if [[ -n "$DELAY" ]]; then
        for ns in "$CLI" "$SRV"; do
            d=$(dev_de "$ns")
            # shellcheck disable=SC2086
            ip netns exec "$ns" tc qdisc add dev "$d" root netem $DELAY $PERDA \
                || erro "tc falhou em ${ns}/${d}.
    Se disse 'Specified qdisc not found', falta o modulo sch_netem:
    sudo dnf install -y kernel-modules-extra && sudo modprobe sch_netem"
        done
    fi

    # Verificacao: sem isto o perfil pode nao ter efeito e ninguem fica sabendo.
    local medido; medido=$(rtt_ms)
    [[ -n "$medido" ]] || erro "ping sem resposta entre os namespaces"
    echo "perfil ${nome}: RTT medido ${medido} ms (alvo ~${alvo} ms)"
    awk -v m="$medido" -v a="$alvo" 'BEGIN {
        if (a == 0) { if (m+0 > 1.0) { print "RTT alto demais para lan"; exit 1 } exit 0 }
        lo = a * 0.6; hi = a * 1.8;
        if (m+0 < lo || m+0 > hi) {
            printf "RTT %s ms fora da faixa [%.1f; %.1f]\n", m, lo, hi; exit 1 }
    }' || erro "o perfil ${nome} NAO produziu o enlace esperado. Nao rode a campanha."
}

estado() {
    for ns in "$CLI" "$SRV"; do
        d=$(dev_de "$ns")
        echo "--- ${ns} (${d}) ---"
        ip netns exec "$ns" ip -br addr show "$d" 2>/dev/null | sed 's/^/  /'
        ip netns exec "$ns" tc qdisc show dev "$d" 2>/dev/null | sed 's/^/  /'
        ip netns exec "$ns" ip route show 2>/dev/null | sed 's/^/  /'
    done
    echo "--- enlace ---"
    echo "  RTT medio: $(rtt_ms) ms"
}

destruir() {
    # Apagar o namespace leva junto a ponta do veth que estava dentro dele.
    ip netns del "$CLI" 2>/dev/null || true
    ip netns del "$SRV" 2>/dev/null || true
    ip link del veth-cli 2>/dev/null || true
    echo "namespaces removidos"
}

case "${1:-}" in
    criar)    criar ;;
    perfil)   perfil "${2:-lan}" ;;
    estado)   estado ;;
    destruir) destruir ;;
    *) erro "uso: rede.sh {criar|perfil <lan|dc|wan>|estado|destruir}" ;;
esac
