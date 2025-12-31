import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import base64

from crypto.keygen import generate_keypair
from crypto.encrypt import encrypt_message
from crypto.decrypt import decrypt_message
from crypto.signature import generate_signing_keypair, sign_message
from stego.embed import embed_data
from stego.extract import extract_data


class PQCStegoUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Post-Quantum Secure Steganography")

        # ================== Key Setup ==================
        self.kem_public_key, self.kem_private_key = generate_keypair()
        self.sign_public_key, self.sign_private_key = generate_signing_keypair()

        # ================== Sender ==================
        sender = tk.LabelFrame(root, text="Sender", padx=10, pady=10)
        sender.grid(row=0, column=0, padx=10, pady=10)

        tk.Label(sender, text="Message").pack()
        self.message_entry = tk.Text(sender, height=4, width=42)
        self.message_entry.pack()

        tk.Button(
            sender,
            text="Encrypt, Sign & Embed",
            command=self.encrypt_and_embed,
            width=30
        ).pack(pady=5)

        tk.Label(sender, text="Ciphertext (Base64)").pack()
        self.sender_cipher = tk.Text(sender, height=4, width=42)
        self.sender_cipher.pack()

        tk.Label(sender, text="Signature (Base64)").pack()
        self.sender_signature = tk.Text(sender, height=4, width=42)
        self.sender_signature.pack()

        tk.Label(sender, text="Cover Image").pack()
        self.cover_image_label = tk.Label(sender)
        self.cover_image_label.pack(pady=5)

        # ================== Receiver ==================
        receiver = tk.LabelFrame(root, text="Receiver", padx=10, pady=10)
        receiver.grid(row=0, column=1, padx=10, pady=10)

        # ---- Stego Image FIRST ----
        tk.Label(receiver, text="Stego Image").pack()
        self.stego_image_label = tk.Label(receiver)
        self.stego_image_label.pack(pady=5)

        tk.Button(
            receiver,
            text="Extract, Decrypt & Verify",
            command=self.extract_and_decrypt,
            width=30
        ).pack(pady=5)

        tk.Label(receiver, text="Extracted Ciphertext (Base64)").pack()
        self.receiver_cipher = tk.Text(receiver, height=4, width=42)
        self.receiver_cipher.pack()

        tk.Label(receiver, text="Extracted Signature (Base64)").pack()
        self.receiver_signature = tk.Text(receiver, height=4, width=42)
        self.receiver_signature.pack()

        tk.Label(receiver, text="Decrypted Message").pack()
        self.output_text = tk.Text(receiver, height=4, width=42)
        self.output_text.pack()

        # ================== Status ==================
        self.status_label = tk.Label(
            root, text="Status: Ready", fg="blue"
        )
        self.status_label.grid(row=1, column=0, columnspan=2, pady=5)

        self.show_image("images/Cover.png", self.cover_image_label)

    # ================== Image Helper ==================
    def show_image(self, path, label):
        img = Image.open(path).resize((250, 250))
        photo = ImageTk.PhotoImage(img)
        label.image = photo
        label.config(image=photo)

    # ================== Sender ==================
    def encrypt_and_embed(self):
        msg = self.message_entry.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showerror("Error", "Enter a message")
            return

        msg_bytes = msg.encode()

        signature = sign_message(self.sign_private_key, msg_bytes)
        ciphertext, _ = encrypt_message(
            self.kem_public_key, msg_bytes, self.sign_private_key
        )

        self.sender_cipher.delete("1.0", tk.END)
        self.sender_cipher.insert(
            tk.END, base64.b64encode(ciphertext).decode()
        )

        self.sender_signature.delete("1.0", tk.END)
        self.sender_signature.insert(
            tk.END, base64.b64encode(signature).decode()
        )

        embed_data("images/Cover.png", ciphertext, "images/stego.png")
        self.show_image("images/stego.png", self.stego_image_label)

        self.status_label.config(
            text="Status: Encrypted, signed & embedded",
            fg="green"
        )

    # ================== Receiver ==================
    def extract_and_decrypt(self):
        try:
            extracted = extract_data("images/stego.png")

            # Show extracted ciphertext first
            self.receiver_cipher.delete("1.0", tk.END)
            self.receiver_cipher.insert(
                tk.END, base64.b64encode(extracted).decode()
            )

            plaintext, signature = decrypt_message(
                self.kem_private_key, extracted, self.sign_public_key
            )

            # Signature becomes visible AFTER decryption
            self.receiver_signature.delete("1.0", tk.END)
            self.receiver_signature.insert(
                tk.END, base64.b64encode(signature).decode()
            )

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, plaintext.decode())

            self.status_label.config(
                text="Status: Signature verified ✔ Decryption successful",
                fg="green"
            )

        except Exception:
            self.status_label.config(
                text="Status: Verification failed ❌",
                fg="red"
            )
            messagebox.showerror(
                "Security Error", "Signature verification failed"
            )


# ================== MAIN ==================
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("980x680")

    root.lift()
    root.attributes("-topmost", True)
    root.after(300, lambda: root.attributes("-topmost", False))

    PQCStegoUI(root)
    root.mainloop()
