# Reprodução da bancada

Este documento tem duas partes. A **Parte A** monta a bancada do zero, para quem
quer reproduzir o artigo inteiro. A **Parte B** produz só os números que ainda
faltam para fechar a submissão, e é a que interessa se a bancada já está de pé.

Plataforma de referência: Rocky Linux 10.2 em modo FIPS, OpenSSL 3.5.5, Intel
Core i3-4005U de dois núcleos. Qualquer distribuição cujo OpenSSL traga ML-KEM e
ML-DSA no provedor padrão deve servir.

---

# Parte A. Montagem

## A.1 Pacotes

```bash
sudo dnf install -y gcc openssl openssl-devel python3 python3-pip \
                    iproute-tc ethtool kernel-modules-extra
python3 -m pip install --user numpy matplotlib pytest
openssl version                                    # precisa ser 3.5 ou superior
openssl list -tls-groups | grep -i mlkem
```

O `kernel-modules-extra` traz o `sch_netem`. Sem ele os perfis de rede com
atraso e perda falham, e o perfil `wan` é o experimento central do artigo.

## A.2 Isolamento da plataforma

Acrescente à linha de comando do kernel e reinicie:

```
isolcpus=1 nohz_full=1 rcu_nocbs=1 nosmt
```

E antes de cada campanha:

```bash
sudo cpupower frequency-set -g performance
sudo sysctl -w kernel.randomize_va_space=0
sudo swapoff -a
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

O servidor roda no núcleo 0 e o cliente no núcleo 1. Isso não é detalhe: numa
versão anterior os dois disputavam o mesmo núcleo, serializavam, e 196 de 210
lotes estouraram o tempo limite.

**Antes de qualquer medição, confira que nada mais usa a bancada:**

```bash
pgrep -af "run.py|bench --mode" || echo "bancada livre"
```

Medir com outra coisa rodando é a forma mais fácil de produzir números que
parecem resultado e são ruído. Aconteceu duas vezes durante este trabalho.

## A.3 Diretórios, compilação e testes

```bash
sudo mkdir -p /dados/{raw,pki,sign} && sudo chown -R "$USER" /dados
git clone <URL-DO-REPOSITORIO> ~/ideia-pq && cd ~/ideia-pq

cd bench
gcc -O2 -Wall -Wextra -o bench harness.c -lssl -lcrypto
gcc -O2 -Wall -Wextra -o microbench_sign microbench_sign.c -lssl -lcrypto -lm
cd ..

python3 -m pytest intent pep -q      # esperado: 33 passed
```

Se algum teste falhar, pare. Uma bancada que emite certificados errados produz
medições perfeitamente consistentes de coisa nenhuma.

## A.4 Rede

```bash
sudo bash scripts/rede.sh criar
sudo bash scripts/rede.sh estado
```

O script descobre o nome da interface dentro do namespace e **verifica o tempo de
ida e volta depois de aplicar o perfil**, recusando-se a prosseguir se o enlace
não corresponder ao pretendido. A versão anterior assumia nomes fixos, o `tc`
falhava em silêncio, e uma campanha inteira rodou com rótulo `wan` e enlace
`lan`.

## A.5 Campanhas

```bash
sudo python3 analysis/run.py --perfil lan --dry-run    # confere o ambiente
sudo python3 analysis/run.py --perfil lan --reps 2     # ensaio, ~10 min
sudo python3 analysis/run.py --perfil lan              # completa, ~2 h
sudo python3 analysis/run.py --perfil wan --modos hs \
     --configs C1,C3,H1,H2,P3 --reps 15                # ~76 min
```

A ordem dos lotes é randomizada com semente fixa (20260913). O contador de
*throttling* térmico é lido antes e depois; se mudar, descarte a sessão.
Acompanhe em outro terminal com `tail -f /dados/execucao.log`.

## A.6 Análise

```bash
python3 analysis/analisar.py --perfil lan --campo tempo --boot 10000
python3 analysis/analisar.py --perfil lan --campo bytes --boot 10000
python3 analysis/analisar.py --perfil wan --campo tempo --boot 10000
```

Saem tabelas `.tex` prontas, `.csv` para conferência e `.json` com tudo.

---

# Parte B. O que ja foi medido e o que falta

## B.1 Concluido

**Controle de congestionamento e MTU.** CUBIC, `tcp_slow_start_after_idle = 1`,
MTU 1500, timestamps habilitados, logo MSS efetivo de 1448 bytes. Estao na
Secao III-B do artigo. Para conferir num ambiente novo:

```bash
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_timestamps
ip netns exec ci-server ip link show | grep mtu
```

**Varredura da janela inicial.** Sete pontos, tres repeticoes cada, em
`dados/varredura_initcwnd_P3.csv`, base da Tabela III. Para repetir:

```bash
# os certificados valem 6 h; reemita antes se a bancada ficou parada
sudo bash scripts/rede.sh criar
sudo python3 analysis/run.py --perfil wan --modos hs --configs P3 --reps 1
sudo bash scripts/varredura-initcwnd.sh
```

O script restaura `initcwnd=10` no fim. Se interromper no meio, **restaure na
mao** com `sudo bash scripts/rede.sh criar`: um `initcwnd` esquecido corrompe em
silencio qualquer campanha posterior, e foi assim que perdemos uma.

## B.2 O que falta

Duas coisas, nenhuma delas de bancada.

**Traducao para ingles.** O CFP exige. O artigo esta em portugues para revisao
interna. Termos a cuidar: *voo* e flight, *degrau* e step, *partida lenta* e
slow start, *janela inicial de congestionamento* e initial congestion window.

**URL ou DOI na secao Disponibilidade.** Procure por `FIXME:URL-DO-REPOSITORIO`
no `paper/main.tex`. Repositorio privado nao serve, porque revisor nao abre;
Zenodo da DOI estavel e aceita os dados brutos que nao cabem no GitHub.

## B.3 Se quiser ir alem

O artigo lista tres direcoes na conclusao, e duas sao baratas nesta bancada.

**Variar a MTU.** O criterio preve que o degrau desapareca com *jumbo frames*,
porque a janela inicial passa a comportar os voos. Basta mudar a MTU dos dois
lados em `scripts/rede.sh` e repetir a varredura.

**Cadeia de um nivel.** Emitir sem o certificado intermediario derruba o voo por
outro caminho, e deve produzir a mesma queda de latencia. Duas intervencoes
independentes sobre o mesmo mecanismo e evidencia bem mais forte que uma.

---

# Problemas conhecidos

**`OPENSSL_CONF` apontando para arquivo inexistente.** Sobrevive no `~/.bashrc`.
Resolva com `sed -i '/OPENSSL_CONF/d' ~/.bashrc ~/.bash_profile ~/.profile` e
`unset OPENSSL_CONF`.

**`Specified qdisc not found`.** Falta o `sch_netem`:
`sudo dnf install -y kernel-modules-extra && sudo modprobe sch_netem`.

**Grupo TLS indisponível em modo FIPS.** O X25519 não aparece. Use `secp256r1` e
`SecP256r1MLKEM768`, que é o que este repositório já faz. O efeito colateral é
benéfico: as células do fatorial passam a diferir apenas pelo acréscimo do
ML-KEM sobre a mesma curva.

**SLH-DSA não negocia handshake TLS 1.3.** Não é defeito da instalação: não há
*code point* de `SignatureScheme` padronizado para o esquema.

**`binario ausente: /root/ideia-pq/bench/bench`.** Sob `sudo` o `HOME` muda. Os
scripts resolvem a raiz por `__file__` por isso; se aparecer, é porque alguma
cópia antiga voltou.

**Medições com máximo absurdo e CV alto.** Quase sempre é outra coisa rodando no
mesmo núcleo. Numa operação de 66 µs, uma única preempção de 1,8 ms leva o
coeficiente de variação de 0,01 para 0,8 sozinha.
