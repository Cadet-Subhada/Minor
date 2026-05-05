from crypto.keygen import generate_keypair
from crypto.signature import generate_signing_keypair
from crypto.encrypt import encrypt_message
from crypto.decrypt import decrypt_message
from stego.embed import embed_data
from stego.extract import extract_data
from blockchain import Blockchain
import hashlib

def main():
    message = b"HELLO POST QUANTUM WORLD"

    print("\n--- KEY GENERATION ---")
    public_key, private_key = generate_keypair()
    sign_public_key, sign_private_key = generate_signing_keypair()

    blockchain = Blockchain() 

    print("\n--- ENCRYPTION ---")
    ciphertext, shared_secret_enc = encrypt_message(
        public_key,
        message,
        sign_private_key
    )

    cipher_hash = hashlib.sha256(ciphertext).hexdigest()
    blockchain.add_block(cipher_hash)

    print("Ciphertext length:", len(ciphertext))

    print("\n--- STEGANOGRAPHY EMBED ---")
    embed_data(
        input_image_path="images/cover.png",
        data_bytes=ciphertext,
        output_image_path="images/stego.png"
    )

    print("\n--- STEGANOGRAPHY EXTRACT ---")
    extracted_ciphertext = extract_data("images/stego.png")

    print("\n--- DECRYPTION ---")

    received_hash = hashlib.sha256(extracted_ciphertext).hexdigest()

    if received_hash != blockchain.chain[-1].data:
        raise Exception("❌ Tampering detected! Data mismatch with blockchain")
    else:
        print("✅ Blockchain verification passed")

    decrypted_message, shared_secret_dec = decrypt_message(
        private_key,
        extracted_ciphertext,
        sign_public_key
    )

    print("\n--- RESULT ---")
    print("Decrypted message:", decrypted_message)
    print("Shared secret match:", shared_secret_enc == shared_secret_dec)
    print("Blockchain valid:", blockchain.verify())


if __name__ == "__main__":
    main()