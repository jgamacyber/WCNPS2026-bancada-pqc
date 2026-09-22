# WCNPS2026-bancada-pqc

# Bancada de medição de mTLS pós-quântico

Código, dados e artigo submetidos ao **WCNPS 2026**:

> *Migração Pós-Quântica em Pipelines DevSecOps: o Custo do Handshake mTLS é um
> Degrau na Janela de Congestionamento*

## A pergunta

Pipelines DevSecOps substituíram segredos estáticos por identidades de carga de
trabalho de vida curta. Isso faz cada tarefa pagar um handshake mTLS completo, a
frio, sem reuso de sessão e com cadeia de certificados apresentada pelos **dois**
lados. A literatura de desempenho de criptografia pós-quântica em TLS foi
construída sobre o perfil da Web, com autenticação unilateral e sessões longas, e
não cobre esse regime. Quanto custa a migração aqui, e onde o custo aparece?

## Os dois resultados

**1. O orçamento de bytes é aditivo e previsível.** Somando os efeitos da troca
de chaves e da autenticação medidos isoladamente, prevê-se o total combinado com
resíduo de 6 bytes em 21 339, ou 0,03%. O valor absoluto também é recuperável da
contagem normativa de campos, dentro de sete bytes. Para cadeia de profundidade
`d` com autenticação mútua, o voo de cada lado cresce aproximadamente
`d(p+s)+s`, com `p` e `s` os tamanhos de chave pública e assinatura do esquema.

**2. Em enlace realista, o custo de latência é um degrau.** Sob 40 ms de ida e
volta com 0,5% de perda:

| | voo do servidor | latência | vs linha de base |
|---|---|---|---|
| H2 (ML-KEM + ML-DSA-44) | 12 160 B | 92,6 ms | +8% |
| P3 (ML-KEM + ML-DSA-65) | 16 042 B | 157,7 ms | **+84%** |

Com MTU 1500 e a opção de *timestamps* habilitada, o MSS efetivo é 1 448 bytes e
a primeira janela comporta 14 480. O critério é

```
d(p+s)+s  >  initcwnd x MSS_efetivo
```

O que generaliza é o critério. O valor de 14 480 bytes é da configuração medida.

## A varredura

Variando só a janela inicial, sem tocar em criptografia:

| `initcwnd` | janela | mediana | queda |
|---|---|---|---|
| 10 | 14 480 B | 157 363 µs | |
| 11 | 15 928 B | 124 858 µs | **−32 506** |
| 12 | 17 376 B | **92 490 µs** | **−32 368** |
| 13 a 40 | | 92 213 a 93 692 µs | platô |

Três coisas saem daí. A resposta é uma escada e não um declive: de doze segmentos
em diante a mediana varia 2% em quinze medições, sem tendência.

São **dois** degraus, não um, e iguais a menos de 0,4%. É consequência de a
autenticação mútua aplicar o critério a cada sentido: com dez segmentos os voos
do servidor (16 042 B) e do cliente (15 877 B) excedem a janela e pagam-se duas
idas e voltas; com onze o cliente passa a caber; com doze cabem os dois. A
literatura de autenticação unilateral não teria como observar isso.

E a varredura **mede o MSS efetivo a partir da latência**: o platô do servidor só
começa em doze, logo MSS < 16 042/11 = 1 458,4; o voo do cliente já cabe em onze,
logo MSS ≥ 15 877/11 = 1 443,4. Uma faixa de quinze bytes que contém 1 448 e
exclui 1 460.

A previsão registrada antes da coleta era de um degrau único entre 10 e 11. Ela
errou por um segmento, e o erro é o que produziu os dois achados acima.

## Estrutura

```
paper/       main.tex e referencias.bib
docs/        REPRODUCAO.md, o guia passo a passo
bench/       instrumentos de medição em C
scripts/     rede.sh (namespaces e perfis), varredura-initcwnd.sh
analysis/    run.py (orquestrador) e analisar.py (fatorial, aditividade, voos)
ace/         autoridade certificadora efêmera que gera as cadeias medidas
intent/      canonização RFC 8785, com 20 testes
pep/         verificador, com 13 testes de segurança
dados/       CSV da varredura; os JSONL brutos não são versionados
```

## Reprodução rápida

```bash
sudo dnf install -y gcc openssl openssl-devel python3 iproute-tc ethtool \
                    kernel-modules-extra
python3 -m pip install --user numpy pytest

cd bench && gcc -O2 -Wall -o bench harness.c -lssl -lcrypto && cd ..
python3 -m pytest intent pep -q                 # 33 testes
sudo bash scripts/rede.sh criar
sudo python3 analysis/run.py --perfil lan --dry-run
sudo python3 analysis/run.py --perfil lan       # ~2 h
sudo python3 analysis/run.py --perfil wan --modos hs --configs C1,C3,H1,H2,P3 --reps 15
python3 analysis/analisar.py --perfil wan --campo tempo --boot 10000
sudo bash scripts/varredura-initcwnd.sh
```

Guia completo, com isolamento da plataforma e problemas conhecidos, em
[docs/REPRODUCAO.md](docs/REPRODUCAO.md).

## Notas sobre o desenho

**Plataforma modesta por método.** Um Intel Core i3-4005U de 2013, sem Turbo
Boost. A escolha segue pqm4 e Bürstinghaus-Steinbach et al.: plataforma restrita
estabelece viabilidade por cima. Neste caso o argumento é ainda mais favorável,
porque a CPU lenta **infla** o termo criptográfico em relação ao de rede e torna
o degrau mais difícil de observar, não mais fácil. As magnitudes são limite
inferior do efeito.

**Modo FIPS.** Retira o X25519 dos grupos disponíveis e obriga a usar
`secp256r1`. O efeito foi benéfico: as células do fatorial passam a diferir
apenas pelo acréscimo do ML-KEM sobre a mesma curva.

**Extensão crítica de 134 bytes.** Os certificados carregam uma extensão privada
herdada de um trabalho anterior, idêntica em todas as configurações. Por ser
constante não afeta comparações, mas integra os voos: sem ela o voo do servidor
em P3 mediria 15 908 bytes e caberia em onze segmentos, e não em doze. O artigo
declara isso na Seção III-B.

**CUBIC, e por que não importa.** O controle de congestionamento é o CUBIC, mas
um handshake de dezenas de kilobytes termina dentro da partida lenta, regime em
que CUBIC, Reno e BBR partem da mesma janela inicial e a duplicam. O resultado
depende de `initcwnd`, não da disciplina.

## Licença

Código sob MIT (`LICENSE`). O texto em `paper/` é dos autores e segue a política
de direitos da IEEE após aceitação.

## Autores

Jaime de Melo Gama da Silva, Daniel Chaves Café e Rômulo F. dos Santos.
Universidade de Brasília, Faculdade de Tecnologia, Departamento de Engenharia
Elétrica.
