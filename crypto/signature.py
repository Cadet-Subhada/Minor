import oqs

# -------- Key generation --------
def generate_signing_keypair():
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


# -------- Sign message --------
def sign_message(private_key, message):
    with oqs.Signature("Dilithium2", secret_key=private_key) as sig:
        signature = sig.sign(message)
    return signature


# -------- Verify signature --------
def verify_signature(public_key, message, signature):
    with oqs.Signature("Dilithium2") as sig:
        return sig.verify(message, signature, public_key)
