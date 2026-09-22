/* =========================================================================
 *  bench/harness.c - Bancada de medicao do IDEIA-PQ
 *
 *  Mede as quatro variaveis de resposta do artigo:
 *    T_emi  emissao na ACE (keygen + extensao + assinatura)
 *    T_hs   handshake mTLS completo ate o primeiro byte de aplicacao
 *    T_ver  verificacao de cadeia + checagem do compromisso de intencao
 *    B_hs   bytes trocados no handshake, no nivel de socket
 *
 *  Compilar:
 *    gcc -O2 -march=native -o bench harness.c -lssl -lcrypto
 *
 *  Sempre executar fixado no nucleo isolado:  taskset -c 1 ./bench ...
 * ========================================================================= */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>

#define OID_INTENT   "1.3.6.1.4.1.99999.1.1"
#define CANON        "RFC8785"          /* mesmo rotulo que ace/extensao.py usa */
#define HASH_LEN     48                 /* SHA-384 */
#define EXT_DER_LEN  114                /* 2 + 3 + 9 + 50 + 50 */
#define OFF_COMPROM  16                 /* onde comeca o compromisso no DER */
#define SPIFFE_SAN   "URI:spiffe://bench.local/ci/repo/stage"

/* ---------------------------------------------------------------- utilidades */

static void morre(const char *msg) {
    fprintf(stderr, "ERRO: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(3);
}

static inline uint64_t agora_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);   /* RAW: imune a ajustes de NTP */
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* percentil sobre vetor JA ordenado */
static uint64_t percentil(const uint64_t *v, size_t n, double p) {
    if (n == 0) return 0;
    size_t i = (size_t)(p * (double)(n - 1) + 0.5);
    return v[i];
}

static void resumo(const char *rotulo, uint64_t *v, size_t n) {
    if (n == 0) return;
    qsort(v, n, sizeof(uint64_t), cmp_u64);
    double soma = 0.0;
    for (size_t i = 0; i < n; i++) soma += (double)v[i];
    fprintf(stderr,
        "%-6s n=%zu  mediana=%.1f us  p95=%.1f us  p99=%.1f us  "
        "min=%.1f  max=%.1f  media=%.1f\n",
        rotulo, n,
        percentil(v, n, 0.50) / 1000.0,
        percentil(v, n, 0.95) / 1000.0,
        percentil(v, n, 0.99) / 1000.0,
        v[0] / 1000.0, v[n - 1] / 1000.0,
        (soma / (double)n) / 1000.0);
}

/* Esquemas sem digest externo (ML-DSA, SLH-DSA, Ed25519) usam md = NULL. */
static const EVP_MD *escolhe_md(EVP_PKEY *k) {
    if (EVP_PKEY_is_a(k, "RSA") || EVP_PKEY_is_a(k, "RSA-PSS") ||
        EVP_PKEY_is_a(k, "EC"))
        return EVP_sha256();
    return NULL;
}

/* Cria e inicializa o contexto de keygen.
 * EC e RSA exigem parametro (curva ou tamanho); os esquemas PQC nao.
 * Aceita "EC", "EC:P-384", "RSA", "RSA:4096", ou o nome direto do algoritmo. */
static EVP_PKEY_CTX *ctx_keygen(const char *alg) {
    char nome[64], par[64];
    const char *dp = strchr(alg, ':');
    if (dp) {
        size_t k = (size_t)(dp - alg);
        if (k >= sizeof nome) k = sizeof nome - 1;
        memcpy(nome, alg, k); nome[k] = 0;
        snprintf(par, sizeof par, "%s", dp + 1);
    } else {
        snprintf(nome, sizeof nome, "%s", alg);
        par[0] = 0;
    }

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, nome, NULL);
    if (!c) return NULL;
    if (EVP_PKEY_keygen_init(c) <= 0) { EVP_PKEY_CTX_free(c); return NULL; }

    if (strcmp(nome, "EC") == 0) {
        const char *curva = par[0] ? par : "P-256";
        if (EVP_PKEY_CTX_set_group_name(c, curva) <= 0) {
            EVP_PKEY_CTX_free(c); return NULL;
        }
    } else if (strcmp(nome, "RSA") == 0 || strcmp(nome, "RSA-PSS") == 0) {
        int bits = par[0] ? atoi(par) : 3072;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits) <= 0) {
            EVP_PKEY_CTX_free(c); return NULL;
        }
    }
    return c;
}

/* ------------------------------------------------- extensao de intencao (DER)
 * ESTA ESTRUTURA PRECISA SER IDENTICA A DE ace/extensao.py. Se as duas
 * divergirem, a ACE emite um certificado que o modo 'ver' nao consegue ler, e o
 * erro so aparece no meio da campanha.
 *
 * IntencaoExt ::= SEQUENCE {          -- 30 70, 2 bytes
 *     versao      INTEGER,            -- 02 01 01, 3 bytes
 *     canon       UTF8String,         -- 0C 07 "RFC8785", 9 bytes
 *     compromisso OCTET STRING (48),  -- 04 30 <48>, 50 bytes
 *     politica    OCTET STRING (48) } -- 04 30 <48>, 50 bytes
 *                                     -- total: 114 bytes
 */
static size_t monta_ext_der(unsigned char *out,
                            const unsigned char *c48,
                            const unsigned char *pol48) {
    const char *canon = CANON;
    size_t clen = strlen(canon);                /* 7 */
    size_t corpo = 3 + (2 + clen) + (2 + HASH_LEN) + (2 + HASH_LEN);
    size_t i = 0;
    out[i++] = 0x30;                            /* SEQUENCE */
    out[i++] = (unsigned char)corpo;            /* 112, forma curta */
    out[i++] = 0x02; out[i++] = 0x01; out[i++] = 0x01;   /* INTEGER 1 */
    out[i++] = 0x0C;                            /* UTF8String */
    out[i++] = (unsigned char)clen;
    memcpy(out + i, canon, clen); i += clen;
    out[i++] = 0x04;                            /* OCTET STRING */
    out[i++] = HASH_LEN;
    memcpy(out + i, c48, HASH_LEN); i += HASH_LEN;
    out[i++] = 0x04;
    out[i++] = HASH_LEN;
    memcpy(out + i, pol48, HASH_LEN); i += HASH_LEN;
    return i;                                   /* == EXT_DER_LEN */
}

/* Extrai o compromisso (48 bytes) da extensao critica do certificado. */
static int extrai_compromisso(X509 *crt, unsigned char *saida48) {
    ASN1_OBJECT *alvo = OBJ_txt2obj(OID_INTENT, 1);
    if (!alvo) return -1;
    int idx = X509_get_ext_by_OBJ(crt, alvo, -1);
    ASN1_OBJECT_free(alvo);
    if (idx < 0) return -1;

    X509_EXTENSION *ex = X509_get_ext(crt, idx);
    ASN1_OCTET_STRING *os = X509_EXTENSION_get_data(ex);
    const unsigned char *p = ASN1_STRING_get0_data(os);
    int len = ASN1_STRING_length(os);
    if (len < (int)EXT_DER_LEN) return -1;

    /* SEQUENCE(2) + INTEGER(3) + UTF8String(2+7) + tag/len do OCTET STRING(2) */
    size_t off = OFF_COMPROM;
    if (p[off - 2] != 0x04 || p[off - 1] != HASH_LEN) return -1;
    memcpy(saida48, p + off, HASH_LEN);
    return 0;
}

/* ------------------------------------------------------------- carga de PKI */

static X509 *le_cert(const char *caminho) {
    FILE *f = fopen(caminho, "r");
    if (!f) { fprintf(stderr, "nao abriu %s: %s\n", caminho, strerror(errno)); exit(2); }
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!c) morre("PEM_read_X509");
    return c;
}

static EVP_PKEY *le_chave(const char *caminho) {
    FILE *f = fopen(caminho, "r");
    if (!f) { fprintf(stderr, "nao abriu %s: %s\n", caminho, strerror(errno)); exit(2); }
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) morre("PEM_read_PrivateKey");
    return k;
}

/* =========================================================================
 *  MODO emi - tempo de emissao na ACE
 * ========================================================================= */
static int modo_emi(const char *alg, const char *ca_crt, const char *ca_key,
                    long n, long warmup, int tau, FILE *out) {
    X509     *ca    = le_cert(ca_crt);
    EVP_PKEY *cakey = le_chave(ca_key);
    const EVP_MD *md = escolhe_md(cakey);

    unsigned char c48[HASH_LEN], pol48[HASH_LEN], der[EXT_DER_LEN];
    RAND_bytes(c48, HASH_LEN);
    RAND_bytes(pol48, HASH_LEN);
    monta_ext_der(der, c48, pol48);

    ASN1_OBJECT *obj_intent = OBJ_txt2obj(OID_INTENT, 1);
    if (!obj_intent) morre("OBJ_txt2obj");

    uint64_t *amostras = calloc((size_t)n, sizeof(uint64_t));
    if (!amostras) morre("calloc");

    long tam_cert = 0;

    for (long it = 0; it < warmup + n; it++) {
        uint64_t t0 = agora_ns();

        /* 1. par de chaves efemero da carga de trabalho */
        EVP_PKEY_CTX *pctx = ctx_keygen(alg);
        if (!pctx) morre("ctx_keygen: algoritmo ou parametro invalido");
        EVP_PKEY *leaf = NULL;
        if (EVP_PKEY_keygen(pctx, &leaf) <= 0) morre("keygen");

        /* 2. montagem do certificado */
        X509 *crt = X509_new();
        X509_set_version(crt, 2);                       /* v3 */
        unsigned char sn[16];
        RAND_bytes(sn, sizeof sn);
        sn[0] &= 0x7F;
        BIGNUM *bn = BN_bin2bn(sn, sizeof sn, NULL);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(crt));
        BN_free(bn);

        X509_set_issuer_name(crt, X509_get_subject_name(ca));
        X509_gmtime_adj(X509_getm_notBefore(crt), -5);   /* delta */
        X509_gmtime_adj(X509_getm_notAfter(crt), tau);
        X509_set_pubkey(crt, leaf);

        X509_EXTENSION *e1 = X509V3_EXT_conf_nid(NULL, NULL,
                                 NID_subject_alt_name, SPIFFE_SAN);
        if (e1) { X509_add_ext(crt, e1, -1); X509_EXTENSION_free(e1); }
        X509_EXTENSION *e2 = X509V3_EXT_conf_nid(NULL, NULL,
                                 NID_key_usage, "critical,digitalSignature");
        if (e2) { X509_add_ext(crt, e2, -1); X509_EXTENSION_free(e2); }
        X509_EXTENSION *e3 = X509V3_EXT_conf_nid(NULL, NULL,
                                 NID_basic_constraints, "critical,CA:FALSE");
        if (e3) { X509_add_ext(crt, e3, -1); X509_EXTENSION_free(e3); }

        /* 3. extensao critica de intencao */
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(os, der, EXT_DER_LEN);
        X509_EXTENSION *ei = X509_EXTENSION_create_by_OBJ(NULL, obj_intent, 1, os);
        if (!ei) morre("X509_EXTENSION_create_by_OBJ");
        X509_add_ext(crt, ei, -1);
        X509_EXTENSION_free(ei);
        ASN1_OCTET_STRING_free(os);

        /* 4. assinatura pela ACE */
        if (X509_sign(crt, cakey, md) == 0) morre("X509_sign");

        uint64_t t1 = agora_ns();

        if (it >= warmup) {
            amostras[it - warmup] = t1 - t0;
            if (tam_cert == 0) tam_cert = i2d_X509(crt, NULL);
            fprintf(out, "{\"op\":\"emi\",\"alg\":\"%s\",\"ns\":%llu,\"cert_bytes\":%ld}\n",
                    alg, (unsigned long long)(t1 - t0), (long)i2d_X509(crt, NULL));
        }

        X509_free(crt);
        EVP_PKEY_free(leaf);
        EVP_PKEY_CTX_free(pctx);
    }

    fprintf(stderr, "cert_bytes=%ld\n", tam_cert);
    resumo("T_emi", amostras, (size_t)n);

    free(amostras);
    ASN1_OBJECT_free(obj_intent);
    EVP_PKEY_free(cakey);
    X509_free(ca);
    return 0;
}

/* =========================================================================
 *  MODO ver - verificacao de cadeia + checagem do compromisso
 * ========================================================================= */

/* A extensao de intencao e CRITICA e desconhecida do OpenSSL, entao o
 * X509_verify_cert a rejeita com UNHANDLED_CRITICAL_EXTENSION. Esse e
 * exatamente o comportamento desejado para um verificador ingenuo (Secao IV-C
 * do artigo). O PEP, porem, COMPREENDE a extensao: para ele ela nao e
 * "unhandled". Aceitamos somente esse erro; qualquer outro segue fatal. */
static int cb_verificar(int ok, X509_STORE_CTX *ctx) {
    if (ok) return 1;
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) return 1;
    /* Qualquer outro erro e fatal, mas imprime a causa: sem isso, uma falha de
     * cadeia aparece so como "handshake falhou" e nao se diagnostica. */
    fprintf(stderr, "verificacao rejeitou (%d): %s [profundidade %d]\n",
            err, X509_verify_cert_error_string(err),
            X509_STORE_CTX_get_error_depth(ctx));
    return 0;
}

static int modo_ver(const char *leaf_crt, const char *ca_crt,
                    long n, long warmup, FILE *out) {
    X509 *leaf = le_cert(leaf_crt);
    X509 *ca   = le_cert(ca_crt);

    unsigned char esperado[HASH_LEN];
    if (extrai_compromisso(leaf, esperado) != 0)
        morre("certificado sem extensao de intencao valida");

    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);
    /* certificados de vida ultracurta: ignora expiracao no microbenchmark */
    X509_VERIFY_PARAM *par = X509_VERIFY_PARAM_new();
    X509_VERIFY_PARAM_set_flags(par, X509_V_FLAG_NO_CHECK_TIME);
    X509_STORE_set1_param(store, par);
    X509_VERIFY_PARAM_free(par);
    X509_STORE_set_verify_cb(store, cb_verificar);

    uint64_t *amostras = calloc((size_t)n, sizeof(uint64_t));
    if (!amostras) morre("calloc");

    for (long it = 0; it < warmup + n; it++) {
        uint64_t t0 = agora_ns();

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, leaf, NULL);
        int ok = X509_verify_cert(ctx);
        int err = ok ? 0 : X509_STORE_CTX_get_error(ctx);
        X509_STORE_CTX_free(ctx);

        unsigned char obtido[HASH_LEN];
        int ok2 = (extrai_compromisso(leaf, obtido) == 0) &&
                  (CRYPTO_memcmp(obtido, esperado, HASH_LEN) == 0);

        uint64_t t1 = agora_ns();

        if (!ok) {
            fprintf(stderr, "ERRO: cadeia rejeitada (%d): %s\n",
                    err, X509_verify_cert_error_string(err));
            exit(3);
        }
        if (!ok2) morre("compromisso de intencao nao confere");
        if (it >= warmup) {
            amostras[it - warmup] = t1 - t0;
            fprintf(out, "{\"op\":\"ver\",\"ns\":%llu}\n",
                    (unsigned long long)(t1 - t0));
        }
    }

    resumo("T_ver", amostras, (size_t)n);
    free(amostras);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(ca);
    return 0;
}

/* =========================================================================
 *  Configuracao comum de SSL_CTX (mTLS, TLS 1.3, sem reuso de sessao)
 * ========================================================================= */
static SSL_CTX *monta_ctx(int servidor, const char *crt, const char *key,
                          const char *ca, const char *grupos,
                          const char *sigalgs) {
    SSL_CTX *ctx = SSL_CTX_new(servidor ? TLS_server_method() : TLS_client_method());
    if (!ctx) morre("SSL_CTX_new");

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Sem reuso: cada conexao paga um handshake completo, que e o objeto medido */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(ctx, 0);

    if (grupos && *grupos && SSL_CTX_set1_groups_list(ctx, grupos) != 1)
        morre("grupo de troca de chaves nao suportado (veja: openssl list -tls-groups)");
    if (sigalgs && *sigalgs && SSL_CTX_set1_sigalgs_list(ctx, sigalgs) != 1)
        fprintf(stderr, "AVISO: sigalgs '%s' nao aceito, usando o padrao\n", sigalgs);

    if (SSL_CTX_use_certificate_chain_file(ctx, crt) != 1) morre("use_certificate_chain_file");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) morre("use_PrivateKey_file");
    if (SSL_CTX_check_private_key(ctx) != 1) morre("chave nao casa com o certificado");
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) morre("load_verify_locations");

    /* mTLS: os dois lados exigem e verificam certificado do par.
     * O callback e obrigatorio aqui: sem ele, o handshake falha com
     * UNHANDLED_CRITICAL_EXTENSION, porque a extensao de intencao e critica e
     * desconhecida do OpenSSL. Um PEP real a compreende; um verificador
     * ingenuo deve mesmo rejeitar (Secao IV-C do artigo). */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       cb_verificar);
    SSL_CTX_set_verify_depth(ctx, 4);
    return ctx;
}

/* =========================================================================
 *  MODO hs-server
 * ========================================================================= */
static int modo_hs_server(const char *bind_ip, int porta, const char *crt,
                          const char *key, const char *ca, const char *grupos,
                          const char *sigalgs, long total) {
    signal(SIGPIPE, SIG_IGN);
    SSL_CTX *ctx = monta_ctx(1, crt, key, ca, grupos, sigalgs);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int um = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &um, sizeof um);

    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)porta);
    a.sin_addr.s_addr = inet_addr(bind_ip);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 2; }
    if (listen(ls, 128) != 0) { perror("listen"); return 2; }

    fprintf(stderr, "servidor ouvindo em %s:%d, %ld conexoes esperadas\n",
            bind_ip, porta, total);

    for (long i = 0; i < total; i++) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) continue;
        setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, &um, sizeof um);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cs);
        if (SSL_accept(ssl) == 1)
            SSL_write(ssl, "K", 1);      /* primeiro byte de aplicacao */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cs);
    }
    close(ls);
    SSL_CTX_free(ctx);
    return 0;
}

/* =========================================================================
 *  MODO hs-client - mede T_hs e B_hs
 * ========================================================================= */
static int modo_hs_client(const char *ip, int porta, const char *crt,
                          const char *key, const char *ca, const char *grupos,
                          const char *sigalgs, long n, long warmup, FILE *out) {
    signal(SIGPIPE, SIG_IGN);
    SSL_CTX *ctx = monta_ctx(0, crt, key, ca, grupos, sigalgs);

    uint64_t *amostras = calloc((size_t)n, sizeof(uint64_t));
    uint64_t *bytes    = calloc((size_t)n, sizeof(uint64_t));
    if (!amostras || !bytes) morre("calloc");

    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)porta);
    a.sin_addr.s_addr = inet_addr(ip);
    int um = 1;

    for (long it = 0; it < warmup + n; it++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
            perror("connect"); close(s); continue;
        }
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &um, sizeof um);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, s);

        uint64_t t0 = agora_ns();
        int r = SSL_connect(ssl);
        char b;
        if (r == 1) r = SSL_read(ssl, &b, 1);   /* ate o 1o byte de aplicacao */
        uint64_t t1 = agora_ns();

        uint64_t lidos = 0, escritos = 0;
        BIO *rb = SSL_get_rbio(ssl), *wb = SSL_get_wbio(ssl);
        if (rb) lidos    = (uint64_t)BIO_number_read(rb);
        if (wb) escritos = (uint64_t)BIO_number_written(wb);

        if (r <= 0) {
            long vr = SSL_get_verify_result(ssl);
            if (vr != X509_V_OK)
                fprintf(stderr, "verificacao do par (%ld): %s\n",
                        vr, X509_verify_cert_error_string(vr));
            morre("handshake mTLS falhou");
        }

        if (it >= warmup) {
            amostras[it - warmup] = t1 - t0;
            bytes[it - warmup]    = lidos + escritos;
            fprintf(out,
                "{\"op\":\"hs\",\"ns\":%llu,\"bytes\":%llu,"
                "\"bytes_r\":%llu,\"bytes_w\":%llu,\"grupo\":\"%s\"}\n",
                (unsigned long long)(t1 - t0),
                (unsigned long long)(lidos + escritos),
                (unsigned long long)lidos, (unsigned long long)escritos,
                grupos ? grupos : "");
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(s);
    }

    resumo("T_hs", amostras, (size_t)n);
    qsort(bytes, (size_t)n, sizeof(uint64_t), cmp_u64);
    fprintf(stderr, "B_hs   mediana=%llu bytes  min=%llu  max=%llu\n",
            (unsigned long long)percentil(bytes, (size_t)n, 0.50),
            (unsigned long long)bytes[0],
            (unsigned long long)bytes[n - 1]);

    free(amostras); free(bytes);
    SSL_CTX_free(ctx);
    return 0;
}

/* ------------------------------------------------------------------ main */

static void uso(void) {
    fprintf(stderr,
"uso: bench --mode <emi|ver|hs-server|hs-client> [opcoes]\n"
"\n"
"  --n <int>          operacoes medidas          (padrao 10000)\n"
"  --warmup <int>     operacoes descartadas      (padrao 2000)\n"
"  --out <arquivo>    JSONL de saida             (padrao stdout)\n"
"  --alg <nome>       algoritmo (modo emi). Ex: ML-DSA-44,\n"
"                     EC:P-256, RSA:3072, SLH-DSA-SHA2-128s\n"
"  --ca-crt/--ca-key  raiz da ACE\n"
"  --crt/--key        certificado e chave de entidade final\n"
"  --leaf <arquivo>   certificado a verificar    (modo ver)\n"
"  --ip/--porta       endereco                   (modos hs-*)\n"
"  --grupos <lista>   grupos TLS                 ex: X25519MLKEM768\n"
"  --sigalgs <lista>  algoritmos de assinatura   ex: mldsa44\n"
"  --tau <seg>        validade do certificado    (padrao 60)\n");
    exit(1);
}

int main(int argc, char **argv) {
    const char *modo = NULL, *alg = "ML-DSA-44", *out_path = NULL;
    const char *ca_crt = NULL, *ca_key = NULL, *crt = NULL, *key = NULL;
    const char *leaf = NULL, *ip = "10.99.0.2", *grupos = NULL, *sigalgs = NULL;
    long n = 10000, warmup = 2000;
    int porta = 4443, tau = 60;

    for (int i = 1; i < argc; i++) {
        #define ARG(nome) (strcmp(argv[i], nome) == 0 && i + 1 < argc)
        if      (ARG("--mode"))    modo = argv[++i];
        else if (ARG("--n"))       n = atol(argv[++i]);
        else if (ARG("--warmup"))  warmup = atol(argv[++i]);
        else if (ARG("--out"))     out_path = argv[++i];
        else if (ARG("--alg"))     alg = argv[++i];
        else if (ARG("--ca-crt"))  ca_crt = argv[++i];
        else if (ARG("--ca-key"))  ca_key = argv[++i];
        else if (ARG("--crt"))     crt = argv[++i];
        else if (ARG("--key"))     key = argv[++i];
        else if (ARG("--leaf"))    leaf = argv[++i];
        else if (ARG("--ip"))      ip = argv[++i];
        else if (ARG("--porta"))   porta = atoi(argv[++i]);
        else if (ARG("--grupos"))  grupos = argv[++i];
        else if (ARG("--sigalgs")) sigalgs = argv[++i];
        else if (ARG("--tau"))     tau = atoi(argv[++i]);
        else uso();
        #undef ARG
    }
    if (!modo) uso();

    FILE *out = stdout;
    if (out_path && !(out = fopen(out_path, "w"))) { perror("fopen"); return 2; }

    int rc = 0;
    if (!strcmp(modo, "emi")) {
        if (!ca_crt || !ca_key) uso();
        rc = modo_emi(alg, ca_crt, ca_key, n, warmup, tau, out);
    } else if (!strcmp(modo, "ver")) {
        if (!leaf || !ca_crt) uso();
        rc = modo_ver(leaf, ca_crt, n, warmup, out);
    } else if (!strcmp(modo, "hs-server")) {
        if (!crt || !key || !ca_crt) uso();
        rc = modo_hs_server(ip, porta, crt, key, ca_crt, grupos, sigalgs, n + warmup);
    } else if (!strcmp(modo, "hs-client")) {
        if (!crt || !key || !ca_crt) uso();
        rc = modo_hs_client(ip, porta, crt, key, ca_crt, grupos, sigalgs, n, warmup, out);
    } else uso();

    if (out != stdout) fclose(out);
    return rc;
}
