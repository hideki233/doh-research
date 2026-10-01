# Arquitetura e Engenharia de Sistemas Command and Control (C2)

Este documento descreve os fundamentos teóricos, estruturais e de rede dos sistemas de Command and Control (C2), analisando tanto os mecanismos de transporte e operação quanto os métodos empregados pela engenharia de detecção (Blue Team) para identificação e contenção.

---

## 1. Fundamentos e Modelo Operacional

Diferente de protocolos de administração remota síncronos e diretos (como SSH, RDP ou Telnet) — que operam tipicamente de fora para dentro e mantêm portas abertas escutando conexões —, as arquiteturas modernas de C2 operam quase exclusivamente no modelo **egress-only** (de dentro para fora) e de forma **assíncrona**.

### Por que Egress-Only?
Dispositivos de segurança corporativos (firewalls com Stateful Packet Inspection, NATs e roteadores de borda) bloqueiam por padrão o tráfego entrante desconhecido. Por outro lado, para permitir a navegação de usuários e a comunicação de sistemas legítimos, as conexões de saída em portas padrão (80/HTTP, 443/HTTPS e 53/DNS) costumam ser permitidas. Sistemas de C2 aproveitam essa assimetria estrutural.

---

## 2. Topologia em Camadas de uma Infraestrutura C2

Em ambientes estruturados, a infraestrutura de controle nunca expõe o servidor central diretamente à internet aberta. A arquitetura é dividida em tiers (camadas):

```
                        [Console do Operador]
                                  │
                       (Canal Seguro / VPN)
                                  ▼
                       [Teamserver Central]
                     (Fila de Tarefas / Banco)
                                  │
           ┌──────────────────────┴──────────────────────┐
           ▼                                             ▼
  [Redirector HTTP/S]                           [Redirector DNS / DoH]
  (Reverse Proxy / CDN)                         (Nameserver Autoritativo)
           │                                             │
           └──────────────────────┬──────────────────────┘
                                  │
                                  ▼
                          [Host / Implante]
```

### Componentes:

1. **Teamserver (Núcleo):**
   - Servidor central que orquestra a comunicação, gerencia o banco de dados de sessões, enfileira tarefas (jobs) e armazena saídas coletadas.
   - Permanece em rede privada, acessível apenas pelos operadores.
2. **Redirectors (Servidores de Borda / Filtros):**
   - Máquinas intermediárias ou instâncias em nuvem públicas que atuam como proxies reversos de tráfego.
   - **Filtragem de Tráfego:** Se a conexão recebida pertencer a crawlers da web, serviços de reputação de IP ou analistas, o redirector exibe uma página inócua (camuflagem). Se contiver cabeçalhos, cookies ou padrões correspondentes ao implante, a conexão é roteada internamente para o Teamserver.
3. **Implante / Agente:**
   - Código executado no endpoint. Ele é configurado como cliente: acorda em intervalos predeterminados, busca instruções e devolve resultados.

---

## 3. O Ciclo de Comunicação (Beaconing, Sleep e Jitter)

O modo de comunicação predominante em C2 assíncrono é o **Beaconing**. O ciclo ocorre sequencialmente:

```
[Check-in Inicial] ──► [Cálculo do Sleep com Jitter] ──► [Polling de Tarefas] ──► [Execução e Exfiltração]
```

### O Desafio da Periodicidade e o Jitter
Se um processo se conecta a um servidor externo a cada 60 segundos exatos, a assinatura temporal da comunicação torna-se evidente para sistemas de detecção de anomalias (análise de séries temporais e periodicidade de tráfego).

Para mitigar a detecção estatística, introduz-se o conceito de **Jitter**:
- **Sleep:** Intervalo base em segundos entre consultas.
- **Jitter (%):** Variabilidade pseudoaleatória aplicada ao intervalo.

$$\text{Intervalo Efetivo} = \text{Sleep} \pm (\text{Sleep} \times \text{random}(0, \text{Jitter}))$$

*Exemplo:* Com base de 100 segundos e jitter de 30%, cada intervalo entre beacons varia aleatoriamente entre 70 e 130 segundos, quebrando a repetição matemática estrita no tráfego de rede.

---

## 4. Mecanismos de Transporte de Rede

Os canais de transporte variam de acordo com as restrições da rede e o nível de inspeção presente no perímetro:

### A. HTTP / HTTPS
- **Mecanismo:** Requisições web comuns (`GET` para receber tarefas e `POST` para envio de dados).
- **Malleable Profiles:** Capacidade de customizar integralmente a requisição HTTP (URIs simulando endpoints legítimos, User-Agents de navegadores padrão, metadados embutidos dentro de cabeçalhos `Cookie` ou parâmetros de formulário).
- **Vantagem:** Mistura-se facilmente com tráfego corporativo de navegação.

### B. DNS e DNS-over-HTTPS (DoH)
- **Mecanismo:**
  - **Saída (Upload):** Os dados são divididos em rótulos codificados em Base32 ou Hexadecimal e transmitidos como subdomínios em consultas do tipo `A`, `AAAA` ou `TXT` (ex: `dados-chunk.c2.dominio.com`).
  - **Entrada (Download/Instruções):** O servidor autoritativo do domínio devolve a instrução empacotada no payload da resposta (ex: dentro do registro `TXT`).
- **Comportamento em Redes Isoladas:** Mesmo que o host não tenha acesso direto à internet via HTTP/443, consultas DNS enviadas ao servidor de nomes interno da rede corporativa são encaminhadas recursivamente até o servidor autoritativo na internet, permitindo a passagem dos dados por canais não roteáveis diretamente.
- **DoH (RFC 8484):** Adiciona criptografia TLS (porta 443) sobre a consulta DNS, impedindo que dispositivos intermediários na rede local inspecionem os nomes consultados ou as respostas retornadas.

---

## 5. Engenharia de Detecção e Telemetria de Segurança (Blue Team)

A identificação de atividades de C2 envolve a análise cruzada entre eventos de rede (Network Detection and Response - NDR) e eventos de host (Endpoint Detection and Response - EDR).

### 1. Detecção em Nível de Rede
- **Análise Espectral e Métricas de Jitter:** Ferramentas de análise estatística de fluxo (como Zeek ou RITA) calculam a variância e autocorrelação de conexões estabelecidas por cada host, conseguindo apontar conexões com padrões de beaconing mesmo com jitter elevado.
- **JA3 / JA4 Fingerprinting:** A negociação inicial do TLS (Client Hello) expõe conjuntos de cifras (ciphersuites), extensões suportadas e curvas elípticas. Esses parâmetros são consolidados em um hash (JA3/JA4). Implantes que utilizam bibliotecas de rede padrão (ex: `urllib` ou `requests` do Python, `WinHTTP` sem ajustes) geram assinaturas que se destacam quando comparadas às de navegadores comerciais (Chrome, Edge, Firefox).
- **Entropia e FQDNs DNS Anômalos:**
  - Detecção de picos de consultas com alta entropia de caracteres (subdomínios que parecem cadeias aleatórias).
  - Comprimento médio de domínio incomumente alto (> 100 caracteres).
  - Alta frequência de domínios recém-registrados (Newly Observed Domains - NODs).

### 2. Detecção em Nível de Host (Endpoint)
- **Processos Desacoplados de Rede:** O EDR monitora quais executáveis iniciam conexões de rede. Processos nativos do sistema operacional que normalmente não realizam comunicação externa (ex: `notepad.exe`, `calc.exe`, utilitários administrativos do sistema) abrindo sockets para a internet geram alertas de severidade crítica imediata.
- **Injeção de Código em Memória:** Verificação de integridade de threads rodando em áreas de memória marcadas com permissões de execução e escrita simultâneas (`PAGE_EXECUTE_READWRITE`), indicando shellcodes residentes em memória sem arquivo correspondente no disco (fileless).
