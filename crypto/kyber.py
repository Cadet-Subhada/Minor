import oqs


class KyberCrypto:
    """
    Wrapper around Kyber768 lattice-based KEM using liboqs.
    This provides quantum-safe encryption and decryption.
    """

    def __init__(self, algorithm="Kyber768"):
        self.algorithm = algorithm

    def generate_keypair(self):
        """
        Generates a Kyber public/private key pair.
        Returns (public_key, secret_key)
        """
        kem = oqs.KeyEncapsulation(self.algorithm)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        kem.free()
        return public_key, secret_key

    def encrypt(self, public_key):
        """
        Encapsulates a shared secret using the public key.
        Returns (ciphertext, shared_secret)
        """
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decrypt(self, secret_key, ciphertext):
        """
        Decapsulates the shared secret using the private key.
        Returns shared_secret
        """
        with oqs.KeyEncapsulation(self.algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
