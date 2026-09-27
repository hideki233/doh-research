import os
import socket
import struct
import urllib.request

TYPE_MAP = {
    "A": 1,
    "TXT": 16,
    "AAAA": 28,
}


def dns_query(domain: str, qtype_name: str = "A") -> bytes:
    trans_id = os.urandom(2)
    flags = 0x0100  # Recursion Desired (RD)
    qdcount = 1
    ancount = nscount = arcount = 0

    header = struct.pack("!HHHHHH", int.from_bytes(trans_id, "big"), flags, qdcount, ancount, nscount, arcount)

    # Codifica rótulos (labels)
    qname = b""
    for label in domain.split("."):
        encoded = label.encode("ascii")
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"

    qtype = TYPE_MAP.get(qtype_name.upper(), 1)
    qclass = 1  # IN (Internet)

    trailer = struct.pack("!HH", qtype, qclass)
    return header + qname + trailer


def send_udp(packet: bytes, server: str = "1.1.1.1", port: int = 53) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5.0)
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
        return data


def send_doh(packet: bytes, endpoint: str = "https://cloudflare-dns.com/dns-query") -> bytes:
    req = urllib.request.Request(
        url=endpoint,
        data=packet,
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return resp.read()


def parse_minimal_response(data: bytes):
    # Header (12 bytes)
    trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F

    print(f"[*] Flags: 0x{flags:04x} | Respostas (ANCOUNT): {ancount} | RCODE: {rcode}")
    if rcode != 0 or ancount == 0:
        return None

    # jumps the questions
    offset = 12
    while data[offset] != 0:
        offset += 1 + data[offset]
    offset += 1 + 4  

    # Reads RR
    if (data[offset] & 0xC0) == 0xC0:
        offset += 2
    else:
        while data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1

    ans_type, ans_class, ans_ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlength]

    return {"type": ans_type, "ttl": ans_ttl, "rdata": rdata}


if __name__ == "__main__":
    target = input("Dominio: ").strip() or "one.one.one.one"
    query_bytes = dns_query(target, "A")


    result = parse_minimal_response(response)
    if result:
        if result["type"] == 1:  # type A (IPv4)
            ip_str = socket.inet_ntoa(result["rdata"])
            print(f"[+] IPv4 resolvido: {ip_str} (TTL: {result['ttl']})")
        else:
            print(f"[+] Resposta recebida (Tipo {result['type']}): {result['rdata']}")