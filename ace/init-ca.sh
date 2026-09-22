#!/usr/bin/env bash
# =============================================================================
#  init-ca.sh - Cria a raiz de uma Autoridade Certificadora Efemera
#
#  Uso:  bash init-ca.sh <NOME>
#  Nomes: EC | RSA | ML-DSA-44 | ML-DSA-65 | SLH-DSA-SHA2-128s
#
#  A cadeia e HOMOGENEA de proposito: a raiz assina com o MESMO esquema da
#  folha. E isso que permite afirmar, na Secao V-A do artigo, que P3 e
#  pos-quantica em todo o caminho de autenticacao, sem assinatura classica
#  escondida na cadeia. Um revisor perguntou exatamente isso.
# =============================================================================
set -euo pipefail
unset OPENSSL_CONF

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
erro() { echo "init-ca.sh: $*" >&2; exit 1; }

[[ $# -eq 1 ]] || erro "uso: init-ca.sh <EC|RSA|ML-DSA-44|ML-DSA-65|SLH-DSA-SHA2-128s>"
NOME="$1"
DIR="${RAIZ}/ace/ca/${NOME}"

if [[ -f "${DIR}/ca.crt" && -f "${DIR}/ca.key" ]]; then
    # Recria se faltar mais de 3 horas de validade. Certificado de raiz vencido
    # no meio da campanha derrubou 196 lotes na primeira tentativa.
    if openssl x509 -in "${DIR}/ca.crt" -noout -checkend 10800 >/dev/null 2>&1; then
        echo "raiz ${NOME} ja existe e segue valida"
        exit 0
    fi
    echo "raiz ${NOME} perto de expirar, recriando"
fi

mkdir -p "$DIR"

case "$NOME" in
    EC)   GEN=(-algorithm EC  -pkeyopt ec_paramgen_curve:P-256) ;;
    RSA)  GEN=(-algorithm RSA -pkeyopt rsa_keygen_bits:3072)    ;;
    *)    GEN=(-algorithm "$NOME")                              ;;
esac

openssl genpkey "${GEN[@]}" -out "${DIR}/ca.key" 2>/dev/null \
    || erro "algoritmo ${NOME} indisponivel nesta build do OpenSSL
    confira com: openssl list -signature-algorithms"
chmod 600 "${DIR}/ca.key"

# 30 dias: a raiz precisa sobreviver a campanha inteira com folga larga.
openssl req -x509 -new -key "${DIR}/ca.key" -days 30 -out "${DIR}/ca.crt" \
    -subj "/CN=IDEIA-PQ ACE ${NOME}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    || erro "falha ao criar o certificado da raiz"

ALG="$(openssl x509 -in "${DIR}/ca.crt" -noout -text | grep -m1 'Signature Algorithm' | sed 's/.*: //')"
echo "raiz ${NOME} criada: ${DIR}/ca.crt"
echo "  algoritmo de assinatura: ${ALG}"
