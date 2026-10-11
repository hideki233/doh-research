# language: Python, file: test_dns.py, runtime: Python 3.10+
import struct
import unittest
from DNS_Research import dns_query, encode, decode, parse_minimal_response
from receiver import parse_qname, build_response
from crypto import derive_key, encrypt_payload, decrypt_payload
from cryptography.exceptions import InvalidTag


class TestDNSProtocol(unittest.TestCase):

    def test_dns_header_specification(self):
        """Valida se o cabeçalho binário obedece rigorosamente aos 12 bytes da RFC 1035."""
        packet = dns_query("google.com", "A")

        # Cabeçalho fixo tem que ter no mínimo 12 bytes
        self.assertGreaterEqual(len(packet), 12)

        # Desempacota os 6 campos de 16-bits do cabeçalho (Big-Endian)
        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])

        # Flags: 0x0100 significa apenas o bit RD (Recursion Desired) ativo
        self.assertEqual(flags, 0x0100)
        # Deve conter exatamente 1 pergunta na seção Question
        self.assertEqual(qdcount, 1)
        # Nenhuma resposta na requisição inicial
        self.assertEqual(ancount, 0)
        self.assertEqual(nscount, 0)
        self.assertEqual(arcount, 0)

    def test_qname_label_encoding(self):
        """Valida se o domínio é fatiado corretamente em rótulos com comprimento prefixado."""
        domain = "api.test.local"
        packet = dns_query(domain, "A")

        # O QNAME começa no byte 12
        qname_bytes = packet[12:]

        # Formato esperado: \x03api \x04test \x05local \x00
        expected_prefix = b"\x03api\x04test\x05local\x00"
        self.assertTrue(qname_bytes.startswith(expected_prefix))

        # Os 4 bytes seguintes devem ser QTYPE=1 (A) e QCLASS=1 (IN)
        trailer_offset = 12 + len(expected_prefix)
        qtype, qclass = struct.unpack("!HH", packet[trailer_offset:trailer_offset + 4])
        self.assertEqual(qtype, 1)
        self.assertEqual(qclass, 1)

    def test_base32_codec_roundtrip(self):
        """Garante que a codificação em labels e a decodificação preservam a integridade dos dados."""
        payload_original = b"Engenharia de Redes & DNS RFC 1035!"
        domain = "c2.example.com"

        fqdns = encode(payload_original, domain)

        # Verifica se gerou pelo menos um FQDN válido
        self.assertGreater(len(fqdns), 0)
        for fqdn in fqdns:
            self.assertTrue(fqdn.endswith(f".{domain}"))
            # Regra da RFC 1035: nenhum label entre pontos pode ter mais de 63 caracteres
            for label in fqdn.split("."):
                self.assertLessEqual(len(label), 63)

        # Decodifica e compara com o original (idempotência)
        payload_recuperado = decode(fqdns, domain)
        self.assertEqual(payload_recuperado, payload_original)

    def test_receiver_parse_qname(self):
        """Testa se a função do receiver extrai o FQDN correto a partir dos bytes da query."""
        domain = "sensor42.infra.local"
        packet = dns_query(domain, "A")

        # parse_qname consome a partir do byte 12
        extracted_name, offset_end = parse_qname(packet, 12)

        self.assertEqual(extracted_name, domain)
        # O offset retornado deve apontar exatamente após o byte nulo \x00
        self.assertEqual(packet[offset_end - 1], 0)

    def test_receiver_build_response_type_a(self):
        """Valida se o receiver gera uma resposta DNS válida do Tipo A apontando para 127.0.0.1."""
        domain = "ping.c2.example.com"
        query_packet = dns_query(domain, "A")
        _, qname_end = parse_qname(query_packet, 12)

        response = build_response(query_packet, qname_end, response_type="A")
        result = parse_minimal_response(response)

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], 1)  # Tipo A
        self.assertEqual(result["ttl"], 60)
        self.assertEqual(result["rdata"], b"\x7f\x00\x00\x01")  # 127.0.0.1

    def test_receiver_build_response_type_txt(self):
        """Valida se o receiver gera uma resposta DNS válida do Tipo TXT com payload de comando."""
        domain = "cmd.c2.example.com"
        query_packet = dns_query(domain, "TXT")
        _, qname_end = parse_qname(query_packet, 12)

        msg_esperada = "Comando de teste 123"
        response = build_response(query_packet, qname_end, response_type="TXT", MSG=msg_esperada)
        result = parse_minimal_response(response)

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], 16)  # Tipo TXT
        self.assertEqual(result["ttl"], 60)

        # Valida a estrutura [comprimento (1B)][texto] do RDATA do TXT
        rdata = result["rdata"]
        txt_len = rdata[0]
        txt_conteudo = rdata[1:1 + txt_len].decode("ascii")

        self.assertEqual(txt_len, len(msg_esperada))
        self.assertEqual(txt_conteudo, msg_esperada)

    def test_crypto_aes_gcm_roundtrip(self):
        """Valida se o AES-256-GCM cifra e decifra preservando a integridade estrita dos bytes."""
        key = derive_key("senha_super_secreta_c2")
        payload = b"Comando confidencial para o host comprometido: whoami /all"

        encrypted = encrypt_payload(payload, key)
        # O blob cifrado deve ter tamanho: len(payload) + 12 (nonce) + 16 (tag MAC)
        self.assertEqual(len(encrypted), len(payload) + 12 + 16)

        decrypted = decrypt_payload(encrypted, key)
        self.assertEqual(decrypted, payload)

    def test_crypto_tamper_detection(self):
        """Valida se o AES-GCM rejeita imediatamente payloads adulterados em trânsito (InvalidTag)."""
        key = derive_key("chave_autenticacao")
        payload = b"Comando legitimo"
        encrypted = bytearray(encrypt_payload(payload, key))

        # Adultera o ultimo byte da mensagem cifrada (flip de bit)
        encrypted[-1] ^= 0x01

        with self.assertRaises(InvalidTag):
            decrypt_payload(bytes(encrypted), key)

    def test_crypto_wrong_key_rejection(self):
        """Valida se uma chave incorreta eh sumariamente rejeitada pelo MAC do GCM."""
        key_correta = derive_key("chave_certa")
        key_errada = derive_key("chave_errada")
        payload = b"Mensagem secreta"

        encrypted = encrypt_payload(payload, key_correta)

        with self.assertRaises(InvalidTag):
            decrypt_payload(encrypted, key_errada)


if __name__ == "__main__":
    unittest.main()
