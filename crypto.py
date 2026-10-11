import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Because AES-256 NEEDS a key that are 256 bits, we pass the key as a sha256 hash
def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode("utf-8")).digest()

def encrypt_payload(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext

def decrypt_payload(encrypted_blob: bytes, key: bytes) -> bytes:
    if len(encrypted_blob) < 12 + 16:
        raise ValueError("Blob criptografado curto demais ou invalido")
    
    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)