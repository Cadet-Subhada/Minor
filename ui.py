import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk

from crypto.keygen import generate_keypair
from crypto.encrypt import encrypt_message
from crypto.decrypt import decrypt_message
from crypto.signature import generate_signing_keypair
from stego.embed import embed_data
from stego.extract import extract_data


class PQCStegoUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Post-Quantum Secure Steganography")

        # ================== Key Setup ==================
        # Receiver keys (Kyber)
        self.kem_public_key, self.kem_private_key = generate_keypair()

        # Sender signing keys (Dilithium)
        self.sign_public_key, self.sign_private_key = generate_signing_keypair()

        # ================== Sender ==================
        sender_frame = tk.LabelFrame(root, text="Sender", padx=12, pady=12)
        sender_frame.grid(row=0, column=0, padx=10, pady=10)

        tk.Label(sender_frame, text="Message to Send").pack()

        self.message_entry = tk.Text(sender_frame, height=6, width=42)
        self.message_entry.pack()

        tk.Button(
            sender_frame,
            text="Encrypt, Sign & Embed",
            command=self.encrypt_and_embed,
            width=28
        ).pack(pady=8)

        # ---- Cover Image ----
        tk.Label(sender_frame, text="Cover Image").pack()
        self.cover_image_label = tk.Label(sender_frame)
        self.cover_image_label.pack(pady=5)

        # ================== Receiver ==================
        receiver_frame = tk.LabelFrame(root, text="Receiver", padx=12, pady=12)
        receiver_frame.grid(row=0, column=1, padx=10, pady=10)

        tk.Button(
            receiver_frame,
            text="Extract, Verify & Decrypt",
            command=self.extract_and_decrypt,
            width=28
        ).pack(pady=8)

        # ---- Stego Image ----
        tk.Label(receiver_frame, text="Stego Image").pack()
        self.stego_image_label = tk.Label(receiver_frame)
        self.stego_image_label.pack(pady=5)

        tk.Label(receiver_frame, text="Decrypted Message").pack()
        self.output_text = tk.Text(receiver_frame, height=6, width=42)
        self.output_text.pack()

        # ================== Status ==================
        self.status_label = tk.Label(
            root,
            text="Status: Ready",
            fg="blue"
        )
        self.status_label.grid(row=1, column=0, columnspan=2, pady=6)

        # Show cover image on startup
        self.show_image("images/cover.png", self.cover_image_label)

    # ================== Image Helper ==================
    def show_image(self, path, label):
        img = Image.open(path)
        img = img.resize((250, 250))
        photo = ImageTk.PhotoImage(img)

        label.image = photo  # prevent garbage collection
        label.config(image=photo)

    # ================== Sender Logic ==================
    def encrypt_and_embed(self):
        message = self.message_entry.get("1.0", tk.END).strip()

        if not message:
            messagebox.showerror("Error", "Please enter a message")
            return

        try:
            ciphertext, _ = encrypt_message(
                self.kem_public_key,
                message.encode("utf-8"),
                self.sign_private_key
            )

            embed_data(
                "images/cover.png",
                ciphertext,
                "images/stego.png"
            )

            # Show stego image after embedding
            self.show_image("images/stego.png", self.stego_image_label)

            self.status_label.config(
                text="Status: Message encrypted, signed, and embedded",
                fg="green"
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ================== Receiver Logic ==================
    def extract_and_decrypt(self):
        try:
            extracted_data = extract_data("images/stego.png")

            decrypted_message, _ = decrypt_message(
                self.kem_private_key,
                extracted_data,
                self.sign_public_key
            )

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(
                tk.END,
                decrypted_message.decode("utf-8")
            )

            self.status_label.config(
                text="Status: Message decrypted and signature verified",
                fg="green"
            )

        except Exception as e:
            self.status_label.config(
                text="Status: Decryption or verification failed",
                fg="red"
            )
            messagebox.showerror("Security Error", str(e))


# ================== MAIN ==================
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("920x420")

    # Force visibility (Linux window manager fix)
    root.lift()
    root.attributes("-topmost", True)
    root.after(300, lambda: root.attributes("-topmost", False))

    app = PQCStegoUI(root)
    root.mainloop()
