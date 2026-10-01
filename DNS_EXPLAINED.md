# Arquitetura e Engenharia de Protocolo DNS (RFC 1035 & RFC 8484)

Este documento detalha o funcionamento mecânico e binário do Domain Name System (DNS), cobrindo desde a hierarquia conceitual da internet até o wire-format exato de pacotes e o encapsulamento moderno com DNS-over-HTTPS (DoH).

---

## 1. Topologia e Resolução Hierárquica

O DNS opera como uma base de dados distribuída e hierárquica em árvore invertida. Nenhuma entidade única mantém o registro de toda a internet.

```
                  . (Root Zone)
           ┌──────────┼──────────┐
          .com       .org       .br (TLDs)
           │                     │
      google.com            registro.br (SLDs)
           │                     │
    api.google.com          registro.registro.br (Subdomínios)
```

### O Fluxo de Resolução Recursiva vs. Autoritativa

1. **Stub Resolver (Cliente local / SO):**
   - Dispara a consulta para o resolver configurado no sistema (`/etc/resolv.conf` ou DHCP), por exemplo, `1.1.1.1` ou o roteador local.
2. **Recursive Resolver (Ex: Cloudflare, Google, Provedor ISP):**
   - É o nó que executa o trabalho pesado. Se ele não tem o dado em cache, ele caminha pela árvore:
   - Consulta um dos **Root Servers** (`a.root-servers.net` até `m.root-servers.net`) perguntando quem responde por `.com`. O root devolve o endereço dos TLD servers de `.com`.
   - Consulta o **TLD Server de `.com`**, que devolve os Authoritative Name Servers delegados para `exemplo.com` (via registros NS).
   - Consulta o **Authoritative Server de `exemplo.com`**, que detém o controle dos registros e devolve a resposta definitiva (Answer).
3. **Cache e TTL:**
   - Cada resposta carrega um valor de **TTL (Time to Live)** em segundos. O Recursive Resolver memoriza essa resposta durante esse intervalo. Enquanto o TTL não expirar, consultas idênticas são respondidas localmente sem tocar nos servidores autoritativos.

---

## 2. O Formato de Mensagem em Nível de Fio (Wire-Format - RFC 1035)

Todas as comunicações DNS — sejam requisições ou respostas, sobre UDP, TCP ou DoH — compartilham exatamente a mesma estrutura básica:

```
+---------------------+
|        Header       |  12 Bytes (Obrigatório)
+---------------------+
|       Question      |  Pergunta feita pelo cliente
+---------------------+
|        Answer       |  Respostas diretas (Resource Records)
+---------------------+
|      Authority      |  Ponteiros para servidores autoritativos (NS)
+---------------------+
|      Additional     |  Registros auxiliares (Glue records, EDNS0/OPT)
+---------------------+
```

---

## 3. Estrutura Binária do Cabeçalho (12 Bytes)

O cabeçalho DNS possui tamanho fixo de 96 bits (12 bytes) e obedece à ordem **Big-Endian** (Network Byte Order).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      ID                       |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    QDCOUNT                    |                    ANCOUNT                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    NSCOUNT                    |                    ARCOUNT                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Campos e Significados:

1. **Transaction ID (16 bits / 2 bytes):**
   - Identificador aleatório gerado pelo cliente. A resposta do servidor precisa obrigatoriamente trazer o mesmo ID para correlacionar a requisição e mitigar ataques de envenenamento de cache (DNS Cache Poisoning / Kaminsky attack).
2. **Flags (16 bits / 2 bytes):**
   - `QR (1 bit)`: `0` para Query (consulta), `1` para Response (resposta).
   - `Opcode (4 bits)`: Tipo de consulta (`0` = Consulta padrão / QUERY).
   - `AA (1 bit)`: Authoritative Answer. Indica se o servidor que respondeu é autoritativo pelo domínio.
   - `TC (1 bit)`: Truncated Response. Se o pacote excedeu 512 bytes em UDP puro sem EDNS0, a resposta é truncada e o cliente deve tentar novamente via TCP.
   - `RD (1 bit)`: Recursion Desired. Quando o cliente solicita que o servidor faça a busca completa até a resposta final.
   - `RA (1 bit)`: Recursion Available. Informa se o servidor suporta resolução recursiva.
   - `Z (3 bits)`: Reservado para uso futuro. Deve ser `0`.
   - `RCODE (4 bits)`: Response Code (Código de retorno):
     - `0`: NOERROR (Sucesso).
     - `1`: FORMERR (Erro de formatação na mensagem recebida).
     - `2`: SERVFAIL (Falha interna do servidor).
     - `3`: NXDOMAIN (Non-Existent Domain — domínio não existe).
     - `5`: REFUSED (Servidor se recusou a executar a consulta).
3. **Contadores de Seções (16 bits cada / 2 bytes cada):**
   - `QDCOUNT`: Quantidade de entradas na seção Question (geralmente `1`).
   - `ANCOUNT`: Quantidade de Resource Records na seção Answer.
   - `NSCOUNT`: Quantidade de Resource Records na seção Authority.
   - `ARCOUNT`: Quantidade de Resource Records na seção Additional.

---

## 4. Codificação de Nomes de Domínio (Labels) e Seção Question

No protocolo DNS, strings como `www.google.com` não são transmitidas com pontos literais. Elas são decompostas em uma cadeia de **labels (rótulos)** prefixados por seus tamanhos em bytes.

### Estrutura da Seção Question:
```
+-- ... --+-- ... --+-- ... --+-- ... --+-- ... --+
|  QNAME (comprimento variável terminado em \x00) |
+-- ... --+-- ... --+-- ... --+-- ... --+-- ... --+
|                 QTYPE (2 bytes)                 |
+-------------------------------------------------+
|                 QCLASS (2 bytes)                |
+-------------------------------------------------+
```

### Regras do QNAME:
1. **Comprimento de Label:** Cada label tem no máximo **63 caracteres**. O byte de prefixo indica o número de bytes subsequentes.
2. **Término Obrigatório:** O fim do nome completo é demarcado por um byte nulo `\x00` (um label de tamanho zero que representa a raiz `.`).
3. **Comprimento Total:** O FQDN completo montado no wire format não pode ultrapassar **255 bytes** (incluindo bytes de tamanho e o terminador).

#### Exemplo prático de codificação: `api.dev.br`
```
Hex:    03 61 70 69  03 64 65 76  02 62 72  00
ASCII:  [3] a  p  i  [3] d  e  v  [2] b  r  [NULL]
```

### Tipos de Registro Comuns (QTYPE):
- `0x0001` (1): **A** (Endereço IPv4, 4 bytes).
- `0x001c` (28): **AAAA** (Endereço IPv6, 16 bytes).
- `0x0005` (5): **CNAME** (Canonical Name — alias para outro domínio).
- `0x0002` (2): **NS** (Name Server autoritativo).
- `0x000f` (15): **MX** (Mail Exchange).
- `0x0010` (16): **TXT** (Texto arbitrário, strings com prefixo de tamanho até 255 bytes).

### Classes (QCLASS):
- `0x0001` (1): **IN** (Internet — praticamente a única usada no mundo moderno).

---

## 5. Seção de Resposta (Answer Resource Record) e Compressão

Cada resposta retornada dentro de `Answer`, `Authority` ou `Additional` obedece ao formato de Resource Record (RR):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                               NAME                            /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              TYPE             |             CLASS             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              TTL                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            RDLENGTH           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/                             RDATA                             /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### O Mecanismo de Compressão de Ponteiro (RFC 1035 - Seção 4.1.4)
Para evitar a duplicação inútil de nomes longos dentro do mesmo pacote, o DNS introduz ponteiros de compressão.
- Um ponteiro é identificado quando os **dois bits mais significativos** de um byte de label estão marcados como `11` (`0xC0` em hexadecimal).
- Em vez de um byte de tamanho de string, os 14 bits restantes formam um deslocamento (offset) medido em bytes a partir do primeiro byte de toda a mensagem DNS (do início do cabeçalho de 12 bytes).

#### Exemplo de Leitura:
Se o parser encontra `0xC0 0x0C`:
1. `0xC0` sinaliza um ponteiro.
2. `0x0C` (12 em decimal) aponta para o byte 12 do pacote.
3. O byte 12 é exatamente onde começa o nome na seção Question. O parser simplesmente "pula" para o offset 12 e reconstrói o nome de lá sem precisar de dados repetidos.

---

## 6. Camada de Transporte: UDP Clássico vs. DoH (RFC 8484)

| Característica | DNS Clássico (RFC 1035) | DNS-over-HTTPS (RFC 8484) |
|---|---|---|
| **Porta / Camada** | UDP (e fallback TCP) na porta 53 | TCP/TLS na porta 443 |
| **Criptografia** | Nenhuma (Cleartext puro, vulnerável a interceptação/spoofing) | Criptografado ponta a ponta (TLS 1.2 / TLS 1.3) |
| **Encapsulamento** | Pacote binário puro transmitido no socket UDP | O mesmo pacote binário dentro do corpo de uma requisição HTTP POST ou GET |
| **Content-Type** | N/A | `application/dns-message` |
| **Inspeção de Rede** | Facilmente analisável por firewalls e DPI (Deep Packet Inspection) | Indistinguível de tráfego HTTPS padrão para a CDN/servidor |

No DoH, o pacote binário gerado pela engenharia da RFC 1035 é mantido intacto. A única diferença é que ele é enviado como o payload bruto (`body`) de uma requisição HTTP `POST` para o endpoint DoH (ex: `https://cloudflare-dns.com/dns-query`), recebendo como resposta HTTP `200 OK` os mesmos bytes binários que um socket UDP devolveria.
