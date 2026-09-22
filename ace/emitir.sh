#!/usr/bin/env bash
# =============================================================================
#  emitir.sh - Autoridade Certificadora Efemera (ACE) do IDEIA-PQ
#
#  Emite um SVID X.509 de vida ultracurta com o compromisso de intencao numa
#  extensao CRITICA.
#
#  Uso:
#    bash emitir.sh <CA> <CSR> <COMPROMISSO_HEX> <POLITICA_HEX> <TAU_S> <SAIDA>
#
#  Exemplo:
#    bash emitir.sh EC /tmp/leaf.csr "$(...96 hex...)" "$(...96 hex...)" 30 /tmp/leaf.crt
#
#  <CA> e o nome do diretorio em ace/ca/, que tambem determina o algoritmo de
#  assinatura da raiz: EC, RSA, ML-DSA-44, ML-DSA-65, SLH-DSA-SHA2-128s.
#
#  A extensao NAO e montada aqui. Ela vem de extensao.py, que e a mesma
#  implementacao que o PEP usa para decodificar. Montar DER em shell foi o que
#  quebrou a primeira tentativa desta bancada.
# =============================================================================
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACE="${RAIZ}/ace"

# O OPENSSL_CONF do ambiente pode apontar para um arquivo com secoes que
# atrapalham a emissao. Neutraliza-se de proposito.
unset OPENSSL_CONF

erro() { echo "emitir.sh: $*" >&2; exit 1; }

[[ $# -eq 6 ]] || erro "uso: emitir.sh <CA> <CSR> <C_HEX> <POL_HEX> <TAU_S> <SAIDA>"

CA_NOME="$1"; CSR="$2"; C_HEX="$3"; POL_HEX="$4"; TAU="$5"; SAIDA="$6"
CA_DIR="${ACE}/ca/${CA_NOME}"

# ---------------------------------------------------------------- validacao
# Validar cedo e o que impede "garbage in, signed garbage out". Um compromisso
# vazio produziria certificado sintaticamente valido e sem nenhuma propriedade
# de seguranca, que foi um bug real desta bancada.
[[ -f "$CSR" ]]                  || erro "CSR nao encontrada: $CSR"
[[ -f "${CA_DIR}/ca.crt" ]]      || erro "raiz ausente: ${CA_DIR}/ca.crt (rode init-ca.sh ${CA_NOME})"
[[ -f "${CA_DIR}/ca.key" ]]      || erro "chave da raiz ausente: ${CA_DIR}/ca.key"
[[ "$C_HEX"   =~ ^[0-9a-fA-F]{96}$ ]] || erro "compromisso deve ter 96 hex (SHA-384), veio '${#C_HEX}' caracteres"
[[ "$POL_HEX" =~ ^[0-9a-fA-F]{96}$ ]] || erro "politica deve ter 96 hex (SHA-384), veio '${#POL_HEX}' caracteres"
[[ "$TAU" =~ ^[0-9]+$ ]] && (( TAU > 0 )) || erro "tau invalido: $TAU"

# ------------------------------------------------------- montagem da extensao
LINHA_EXT="$(python3 "${ACE}/extensao.py" "$C_HEX" "$POL_HEX")" \
    || erro "extensao.py falhou ao codificar a extensao"
[[ "$LINHA_EXT" == *"DER:"* ]] || erro "extensao.py devolveu saida inesperada"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "${TMP}/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth,serverAuth
subjectAltName=URI:spiffe://ideia-pq.unb.br/ci/demo/build
${LINHA_EXT}
EOF

# Serial aleatorio de 20 bytes. Serial sequencial em CA que emite por tarefa
# vaza a taxa de emissao da organizacao.
SERIAL="$(openssl rand -hex 20)"

# ------------------------------------------------------------------ emissao
# -not_before/-not_after com precisao de segundos: 'days' so tem granularidade
# diaria e nao serve para tau na casa das dezenas de segundos.
AGORA=$(date -u +%s)
NB=$(date -u -d "@$((AGORA - 5))"        +%Y%m%d%H%M%SZ)   # delta = 5 s
NA=$(date -u -d "@$((AGORA + TAU))"      +%Y%m%d%H%M%SZ)

openssl x509 -req -in "$CSR" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -set_serial "0x${SERIAL}" \
    -not_before "$NB" -not_after "$NA" \
    -extfile "${TMP}/ext.cnf" \
    -out "$SAIDA" 2>"${TMP}/err" \
  || { echo "--- saida do openssl ---" >&2; cat "${TMP}/err" >&2; \
       erro "openssl x509 -req falhou"; }

# --------------------------------------------------- verificacao da emissao
# A ACE confere o proprio trabalho. Sem isto, um certificado sem a extensao
# passaria adiante e so seria detectado horas depois, na analise.
DER="${TMP}/saida.der"
openssl x509 -in "$SAIDA" -outform DER -out "$DER"

IDEIA_RAIZ="$RAIZ" python3 - "$DER" "$C_HEX" "$POL_HEX" <<'PYEOF' || erro "verificacao pos-emissao falhou"
import os, sys
raiz = os.environ["IDEIA_RAIZ"]
sys.path.insert(0, os.path.join(raiz, "ace"))
sys.path.insert(0, os.path.join(raiz, "pep"))
from extensao import decodificar_extensao
from verificador import extrair_extensao_critica

der = open(sys.argv[1], "rb").read()
valor, critica = extrair_extensao_critica(der)
if len(valor) != 114:
    sys.exit("extensao com %d bytes, esperava 114" % len(valor))
if not critica:
    sys.exit("extensao emitida sem o bit critical")
_, c, pol = decodificar_extensao(valor)
if c.hex() != sys.argv[2].lower():
    sys.exit("compromisso gravado nao confere com o solicitado")
if pol.hex() != sys.argv[3].lower():
    sys.exit("politica gravada nao confere com a solicitada")
PYEOF

echo "emitido: $SAIDA  (CA=${CA_NOME}, tau=${TAU}s, serial=0x${SERIAL:0:16}...)"
