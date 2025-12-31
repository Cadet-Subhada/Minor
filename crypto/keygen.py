# Kyber key generation
import oqs
import base64

def generate_keys():
    with oqs.KeyEncapsulation("Kyber768") as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

    with open("crypto/public.key", "wb") as f:
        f.write(base64.b64encode(public_key))

    with open("crypto/private.key", "wb") as f:
        f.write(base64.b64encode(private_key))

    print("Kyber key pair generated successfully.")

if __name__ == "__main__":
    generate_keys()
