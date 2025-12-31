import oqs
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.signature import sign_message

def encrypt_message(public_key, message, sign_private_key):
    # ---- Kyber key exchange ----
    kem = oqs.KeyEncapsulation("Kyber512")
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # ---- Dilithium signature ----
    signature = sign_message(sign_private_key, message)

    # ---- Combine message + signature ----
    payload = struct.pack(">I", len(signature)) + signature + message

    # ---- AES-GCM encryption ----
    key = shared_secret[:32]
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted_payload = aesgcm.encrypt(nonce, payload, None)

    return ciphertext + nonce + encrypted_payload, shared_secret
