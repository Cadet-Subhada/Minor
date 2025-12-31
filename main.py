from crypto.keygen import generate_keypair
from crypto.encrypt import encrypt_message
from crypto.decrypt import decrypt_message
from stego.embed import embed_data
from stego.extract import extract_data


def main():
    message = b"HELLO POST QUANTUM WORLD"

    print("\n--- KEY GENERATION ---")
    public_key, private_key = generate_keypair()

    print("\n--- ENCRYPTION ---")
    ciphertext, shared_secret_enc = encrypt_message(public_key, message)
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
    decrypted_message, shared_secret_dec = decrypt_message(
        private_key, extracted_ciphertext
    )

    print("\n--- RESULT ---")
    print("Decrypted message:", decrypted_message)
    print("Shared secret match:", shared_secret_enc == shared_secret_dec)


if __name__ == "__main__":
    main()
