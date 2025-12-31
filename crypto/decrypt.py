import oqs
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.signature import verify_signature

def decrypt_message(private_key, data, sign_public_key):
    kem = oqs.KeyEncapsulation("Kyber512", secret_key=private_key)
    ct_len = kem.details["length_ciphertext"]

    ciphertext = data[:ct_len]
    nonce = data[ct_len:ct_len + 12]
    encrypted_payload = data[ct_len + 12:]

    shared_secret = kem.decap_secret(ciphertext)

    key = shared_secret[:32]
    aesgcm = AESGCM(key)
    payload = aesgcm.decrypt(nonce, encrypted_payload, None)

    # ---- Extract signature ----
    sig_len = struct.unpack(">I", payload[:4])[0]
    signature = payload[4:4 + sig_len]
    message = payload[4 + sig_len:]

    # ---- Verify signature ----
    if not verify_signature(sign_public_key, message, signature):
        raise ValueError("Signature verification failed")

    return message, shared_secret
