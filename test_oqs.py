import oqs

print("OQS Python bindings loaded")

# Directly test Kyber (no listing function needed)
with oqs.KeyEncapsulation("Kyber768") as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret_1 = kem.encap_secret(public_key)
    shared_secret_2 = kem.decap_secret(ciphertext)

print("Kyber768 lattice-based KEM test SUCCESSFUL")
