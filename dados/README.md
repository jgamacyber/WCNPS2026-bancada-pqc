# Dados

`varredura_initcwnd_P3.csv` está versionado: são 21 linhas e é a base da
Tabela III do artigo. Colunas: `initcwnd`, janela em bytes com MSS de 1448,
repetição, mediana em microssegundos e voo do servidor em bytes.

Os JSONL das campanhas **não** estão versionados: são 585 arquivos, um por lote,
com uma linha por operação. Para trazê-los da bancada:

```bash
cp /dados/raw/*.jsonl dados/raw/
cp /dados/raw/sessao_*.json dados/raw/
```

Se quiser versioná-los, comprima antes, porque o conjunto passa de 100 MB
descompactado:

```bash
tar -czf dados/raw-lan.tar.gz -C /dados/raw $(cd /dados/raw && ls *_lan_*.jsonl)
tar -czf dados/raw-wan.tar.gz -C /dados/raw $(cd /dados/raw && ls *_wan_*.jsonl)
```

Acima de 100 MB o GitHub exige Git LFS. Para artigo, depositar no Zenodo e citar
o DOI na seção de Disponibilidade costuma ser melhor: o DOI é estável, o revisor
consegue abrir, e cabem os dados inteiros.

## Formato

Modos `emi` e `ver`:

```json
{"op": "emi", "alg": "ML-DSA-44", "ns": 3901244, "cert_bytes": 4128}
```

Modo `hs`, no cliente:

```json
{"op": "hs", "grupo": "MLKEM768", "ns": 157656000,
 "bytes": 31918, "bytes_r": 16042, "bytes_w": 15877}
```

`bytes_r` é o que o cliente recebeu, isto é, o voo do servidor. É esse o campo
que determina se o handshake cabe na primeira janela de congestionamento, e é a
última coluna da Tabela II do artigo.

## Metadados

`sessao_<perfil>.json` guarda a semente, as configurações, o número de execuções,
a contagem de falhas e o contador de *throttling* térmico antes e depois. Sessão
em que o contador mudou deve ser descartada.
