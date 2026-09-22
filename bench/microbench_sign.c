/* ===========================================================================
 *  microbench_sign.c - Isola o tempo de ASSINATURA do tempo de geracao de
 *  chave, que o modo 'emi' do harness mede junto.
 *
 *  Por que isso importa: T_emi = geracao de chave + montagem + assinatura.
 *  Como a geracao de chave do RSA procura primos, ela tem variabilidade
 *  propria, sem nenhuma relacao com o laco de rejeicao do ML-DSA. Enquanto as
 *  duas etapas estiverem somadas, a atribuicao da cauda ao Fiat-Shamir with
 *  Aborts continua sendo hipotese, e o parecer do WCNPS aponta exatamente isso
 *  (itens M-03 e E3).
 *
 *  Este programa gera UMA chave, descarta o custo dela, e mede so
 *  EVP_DigestSign repetidas vezes sobre a mesma chave. Se a cauda continuar
 *  aparecendo no ML-DSA e nao no SLH-DSA, a variancia esta na assinatura.
 *
 *  Compilar:
 *    rm -f microbench_sign
 *    gcc -O2 -Wall -Wextra -o microbench_sign microbench_sign.c -lssl -lcrypto -lm
 *
 *  Usar (sempre no nucleo isolado, como o resto da bancada):
 *    taskset -c 1 ./microbench_sign --alg ML-DSA-44   --n 5000 --warmup 500 \
 *        --out /dados/raw/sign_ML-DSA-44_0.jsonl
 *
 *  Algoritmos aceitos: qualquer nome que o OpenSSL 3.5 conheca, mais a forma
 *  "EC:<curva>" e "RSA:<bits>" para os classicos. Exemplos:
 *    EC:P-256   RSA:3072   ML-DSA-44   ML-DSA-65   SLH-DSA-SHA2-128s
 *
 *  Saida: um JSON por linha, {"op":"sign","alg":...,"ns":...,"sig_bytes":...}
 *  O mesmo formato que o analise_cauda.py ja le (campo "ns").
 * ======================================================================== */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static void morre(const char *msg)
{
    fprintf(stderr, "erro: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static uint64_t agora_ns(void)
{
    struct timespec ts;
    /* MONOTONIC_RAW nao sofre ajuste de NTP nem escorregamento de frequencia. */
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t percentil(const uint64_t *v, size_t n, double p)
{
    if (n == 0) return 0;
    size_t i = (size_t)(p * (double)(n - 1) + 0.5);
    return v[i >= n ? n - 1 : i];
}

/* Monta o contexto de geracao de chave, aceitando "EC:P-256" e "RSA:3072". */
static EVP_PKEY_CTX *ctx_keygen(const char *alg)
{
    char nome[64], param[64];
    const char *dp = strchr(alg, ':');

    if (dp) {
        size_t n = (size_t)(dp - alg);
        if (n >= sizeof nome) morre("nome de algoritmo longo demais");
        memcpy(nome, alg, n);
        nome[n] = '\0';
        snprintf(param, sizeof param, "%s", dp + 1);
    } else {
        snprintf(nome, sizeof nome, "%s", alg);
        param[0] = '\0';
    }

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, nome, NULL);
    if (!c) morre("EVP_PKEY_CTX_new_from_name");
    if (EVP_PKEY_keygen_init(c) <= 0) morre("EVP_PKEY_keygen_init");

    if (param[0]) {
        if (strcmp(nome, "EC") == 0) {
            if (EVP_PKEY_CTX_set_group_name(c, param) <= 0)
                morre("curva desconhecida (use secp256r1 ou P-256)");
        } else if (strcmp(nome, "RSA") == 0) {
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(c, atoi(param)) <= 0)
                morre("EVP_PKEY_CTX_set_rsa_keygen_bits");
        }
    }
    return c;
}

/* ML-DSA e SLH-DSA sao assinaturas "puras": o digest vai NULL. ECDSA e RSA
 * precisam de um digest explicito. */
static int e_puro(const char *alg)
{
    return strncmp(alg, "ML-DSA", 6) == 0 || strncmp(alg, "SLH-DSA", 7) == 0;
}

static void uso(void)
{
    fprintf(stderr,
"uso: microbench_sign --alg <alg> [--n N] [--warmup W] [--msg BYTES] [--out ARQ]\n"
"  --alg     EC:P-256 | RSA:3072 | ML-DSA-44 | ML-DSA-65 | SLH-DSA-SHA2-128s\n"
"  --n       assinaturas medidas          (padrao 5000)\n"
"  --warmup  assinaturas descartadas      (padrao 500)\n"
"  --msg     tamanho da mensagem em bytes (padrao 114, o da extensao)\n"
"  --out     arquivo JSONL de saida       (padrao: so o resumo em stderr)\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *alg = NULL, *saida = NULL;
    long n = 5000, warmup = 500, tam_msg = 114;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--alg")    && i + 1 < argc) alg     = argv[++i];
        else if (!strcmp(argv[i], "--n")      && i + 1 < argc) n       = atol(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup  = atol(argv[++i]);
        else if (!strcmp(argv[i], "--msg")    && i + 1 < argc) tam_msg = atol(argv[++i]);
        else if (!strcmp(argv[i], "--out")    && i + 1 < argc) saida   = argv[++i];
        else uso();
    }
    if (!alg || n <= 0 || warmup < 0 || tam_msg <= 0) uso();

    /* ---- geracao da chave, FORA da medicao -------------------------------- */
    EVP_PKEY_CTX *kctx = ctx_keygen(alg);
    EVP_PKEY *pkey = NULL;
    uint64_t t_key = agora_ns();
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) morre("EVP_PKEY_keygen");
    t_key = agora_ns() - t_key;
    EVP_PKEY_CTX_free(kctx);
    fprintf(stderr, "chave gerada em %.1f us (nao entra na medicao)\n",
            (double)t_key / 1000.0);

    unsigned char *msg = malloc((size_t)tam_msg);
    if (!msg) morre("malloc");
    if (RAND_bytes(msg, (int)tam_msg) != 1) morre("RAND_bytes");

    const char *digest = e_puro(alg) ? NULL : "SHA256";

    /* Descobre o tamanho maximo de assinatura uma vez, para nao realocar. */
    size_t cap = 0;
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if (!md) morre("EVP_MD_CTX_new");
        if (EVP_DigestSignInit_ex(md, NULL, digest, NULL, NULL, pkey, NULL) <= 0)
            morre("EVP_DigestSignInit_ex (algoritmo suportado?)");
        if (EVP_DigestSign(md, NULL, &cap, msg, (size_t)tam_msg) <= 0)
            morre("EVP_DigestSign (sondagem de tamanho)");
        EVP_MD_CTX_free(md);
    }
    unsigned char *sig = malloc(cap);
    if (!sig) morre("malloc sig");

    uint64_t *amostras = calloc((size_t)n, sizeof(uint64_t));
    if (!amostras) morre("calloc");

    FILE *out = NULL;
    if (saida) {
        out = fopen(saida, "w");
        if (!out) morre("nao consegui abrir o arquivo de saida");
    }

    size_t ultimo_tam = 0;

    /* ---- laco de medicao --------------------------------------------------
     * Cada iteracao cria e destroi o EVP_MD_CTX. E o mesmo padrao de uso de uma
     * ACE que assina requisicoes independentes, e evita que estado interno de
     * um contexto reaproveitado mascare a variabilidade do laco de rejeicao. */
    for (long it = 0; it < warmup + n; it++) {
        /* Mensagem nova a cada assinatura: com mensagem fixa, o numero de
         * iteracoes do laco de rejeicao poderia se repetir e a cauda sumiria. */
        if (RAND_bytes(msg, (int)tam_msg) != 1) morre("RAND_bytes");

        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if (!md) morre("EVP_MD_CTX_new");

        uint64_t t0 = agora_ns();
        if (EVP_DigestSignInit_ex(md, NULL, digest, NULL, NULL, pkey, NULL) <= 0)
            morre("EVP_DigestSignInit_ex");
        size_t tam = cap;
        if (EVP_DigestSign(md, sig, &tam, msg, (size_t)tam_msg) <= 0)
            morre("EVP_DigestSign");
        uint64_t dt = agora_ns() - t0;

        EVP_MD_CTX_free(md);

        if (it >= warmup) {
            amostras[it - warmup] = dt;
            ultimo_tam = tam;
            if (out)
                fprintf(out,
                        "{\"op\":\"sign\",\"alg\":\"%s\",\"ns\":%llu,"
                        "\"sig_bytes\":%zu}\n",
                        alg, (unsigned long long)dt, tam);
        }
    }
    if (out) fclose(out);

    /* ---- resumo ----------------------------------------------------------- */
    qsort(amostras, (size_t)n, sizeof(uint64_t), cmp_u64);
    double med  = (double)percentil(amostras, (size_t)n, 0.50) / 1000.0;
    double p95  = (double)percentil(amostras, (size_t)n, 0.95) / 1000.0;
    double p99  = (double)percentil(amostras, (size_t)n, 0.99) / 1000.0;
    double mini = (double)amostras[0] / 1000.0;
    double maxi = (double)amostras[n - 1] / 1000.0;

    double soma = 0.0;
    for (long i = 0; i < n; i++) soma += (double)amostras[i] / 1000.0;
    double media = soma / (double)n;
    double var = 0.0;
    for (long i = 0; i < n; i++) {
        double d = (double)amostras[i] / 1000.0 - media;
        var += d * d;
    }
    var /= (double)(n - 1);
    double cv = media > 0.0 ? (var > 0.0 ? (sqrt(var) / media) : 0.0) : 0.0;

    fprintf(stderr,
        "alg=%s  n=%ld  assinatura=%zu bytes\n"
        "  mediana=%.1f us  p95=%.1f  p99=%.1f  min=%.1f  max=%.1f\n"
        "  media=%.1f us  CV=%.4f  penalidade de fila (1+CV^2)=%.3f\n",
        alg, n, ultimo_tam, med, p95, p99, mini, maxi, media, cv,
        1.0 + cv * cv);

    free(amostras); free(sig); free(msg);
    EVP_PKEY_free(pkey);
    return 0;
}
