# doh-research

[![Tests](https://github.com/hideki233/doh-research/actions/workflows/tests.yml/badge.svg)](https://github.com/hideki233/doh-research/actions/workflows/tests.yml)

Laboratório prático de pesquisa, implementação e análise de tráfego DNS em baixo nível (RFC 1035) e DNS-over-HTTPS (DoH, RFC 8484) em Python puro.

O projeto aborda a montagem manual de mensagens binárias em formato de rede (wire-format), mecanismos de transporte híbrido (UDP socket e DoH via HTTPS POST), dissecação de pacotes e transporte de dados estruturados em subdomínios utilizando codificação Base32.

---

## Componentes do Repositório

### 1. Núcleo de Protocolo (`DNS_Research.py`)
- **Montagem de Pacote RFC 1035:** Construção de cabeçalhos de 12 bytes via `struct.pack` com alinhamento Big-Endian (`!HHHHHH`).
- **Codificação de Rótulos (Labels):** Conversão de nomes FQDN para o formato de tamanho prefixado em bytes terminado em `\x00`.
- **Camada de Transporte:**
  - `send_udp`: Envio clássico via socket UDP para porta 53 (ou customizada).
  - `send_doh`: Encapsulamento da query em requisições HTTPS POST com cabeçalho `Content-Type: application/dns-message` (RFC 8484) direcionadas a resolvers públicos (ex: Cloudflare `1.1.1.1`).
- **Parser de Respostas:** Consumo sequencial do cabeçalho, decodificação de flags e `RCODE`, descarte da seção Question e descompressão de ponteiros de nome (`0xC0`).
- **Camada de Codificação/Decodificação:**
  - `encode`: Fatiamento de payloads em blocos Base32 de até 63 caracteres respeitando as restrições da RFC 1035.
  - `decode`: Remontagem e decodificação do fluxo de dados a partir de nomes de domínio completos (FQDN).

### 2. Servidor de Recepção (`receiver.py`)
- Escuta UDP local na porta definida (`8080`).
- Implementa `parse_qname` para consumir labels diretamente do fluxo de bytes da query recebida.
- Filtra consultas direcionadas ao domínio de controle (`APEX_DOMAIN`) e extrai os payloads enviados pelos clientes.

### 3. Emissor de Teste (`test_sender.py`)
- Script auxiliar para validação do pipeline de transmissão local.
- Codifica uma mensagem de teste, monta a query binária e dispara o pacote UDP contra o `receiver.py`.

### 4. CLI Unificada (`cli.py`)
- Ponto de entrada consolidado utilizando `argparse`.
- Permite subir o servidor (`server`), enviar payloads fracionados em sessões (`send`) ou resolver domínios diretamente via DoH/UDP (`query`).

### 5. Suíte de Testes Automatizados (`test_dns.py`)
- Testes unitários com `unittest` cobrindo especificação binária da RFC 1035, encoding Base32, fatiamento de rótulos e respostas bidirecionais (A e TXT).
- *Nota:* A estrutura e os casos de teste deste arquivo foram gerados com auxílio de Inteligência Artificial para acelerar o processo de desenvolvimento e garantir cobertura rápida das especificações do protocolo.

---

## Documentação Técnica Inclusa

- [`DNS_EXPLAINED.md`](./DNS_EXPLAINED.md): Guia aprofundado cobrindo o wire-format do DNS, resolução recursiva vs. autoritativa, campos de cabeçalho, cálculo de ponteiros de compressão e diferenças arquiteturais entre UDP puro e DoH.
- [`C2_ARCHITECTURE.md`](./C2_ARCHITECTURE.md): Análise técnica de arquiteturas Command and Control (C2), cobrindo o modelo egress-only assíncrono, cálculo de sleep com jitter, topologia em camadas (Teamserver e Redirectors) e métodos de detecção defensiva (Blue Team / NDR / EDR).

---

## Execução Rápida via CLI

### 1. Resolução Direta de Domínio via DoH
```bash
python3 cli.py query google.com --type A --transport doh
```

### 2. Transmissão Completa (Servidor & Cliente em Sessões)
Terminal 1 (Inicia o receptor em escuta):
```bash
python3 cli.py server --port 8080 --domain c2.example.com --type TXT --msg "ACK_OK"
```

Terminal 2 (Transmite dados fragmentados em sessões ordenadas):
```bash
python3 cli.py send --data "Engenharia de Redes & DNS RFC 1035" --domain c2.example.com --port 8080
```

### 3. Executando os Testes Unitários
Valida todas as camadas do protocolo localmente em milissegundos:
```bash
python3 -m unittest -v test_dns.py
```
