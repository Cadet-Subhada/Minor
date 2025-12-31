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
        # ================= ROOT =================
        self.root = root
        self.root.title("Post-Quantum Secure Steganography")
        self.root.geometry("1450x850")
        self.root.configure(bg="#1e1e1e")

        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=1)
        root.grid_columnconfigure(2, weight=0)

        # ================= TITLE =================
        tk.Label(
            root,
            text="POST-QUANTUM SECURE STEGANOGRAPHY PIPELINE",
            font=("Helvetica", 18, "bold"),
            fg="#eeeeee",
            bg="#1e1e1e"
        ).grid(row=0, column=0, columnspan=3, pady=16)

        # ================= KEYS =================
        self.kem_public_key, self.kem_private_key = generate_keypair()
        self.sign_public_key, self.sign_private_key = generate_signing_keypair()

        # ================= MAIN CONTAINER =================
        container = tk.Frame(root, bg="#1e1e1e")
        container.grid(row=1, column=0, columnspan=2, sticky="n")

        # ================= SENDER =================
        sender = self._panel(container, "SENDER")
        sender.grid(row=0, column=0, padx=20, pady=10, sticky="n")

        self.message_entry = self._step_text(
            sender, "STEP 1: Plaintext Message", "#fff6e5", False
        )

        tk.Button(
            sender,
            text="Encrypt → Sign → Embed",
            bg="#3949ab",
            fg="white",
            width=42,
            font=("Helvetica", 10, "bold"),
            command=self.encrypt_and_embed
        ).pack(pady=10)

        self.sender_cipher = self._step_text(
            sender, "STEP 2: Encrypted Ciphertext (Base64)", "#e8f0ff", True
        )

        self.sender_signature = self._step_text(
            sender, "STEP 3: Digital Signature (Dilithium)", "#e8fff3", True
        )

        step4 = self._step_box(sender, "STEP 4: Cover Image")
        self.cover_image_label = tk.Label(step4, bg="#1e1e1e")
        self.cover_image_label.pack(pady=6)

        # ================= RECEIVER =================
        receiver = self._panel(container, "RECEIVER")
        receiver.grid(row=0, column=1, padx=20, pady=10, sticky="n")

        step5 = self._step_box(receiver, "STEP 5: Received Stego Image")
        self.stego_image_label = tk.Label(step5, bg="#1e1e1e")
        self.stego_image_label.pack(pady=6)

        tk.Button(
            receiver,
            text="Extract → Decrypt → Verify",
            bg="#00897b",
            fg="white",
            width=42,
            font=("Helvetica", 10, "bold"),
            command=self.extract_and_decrypt
        ).pack(pady=10)

        self.receiver_cipher = self._step_text(
            receiver, "STEP 6: Extracted Ciphertext (Base64)", "#e8f0ff", True
        )

        self.receiver_signature = self._step_text(
            receiver, "STEP 7: Recovered Digital Signature", "#e8fff3", True
        )

        self.output_text = self._step_text(
            receiver, "STEP 8: Decrypted Message", "#fff6e5", True
        )

        # ================= NIST SIDEBAR =================
        nist = tk.LabelFrame(
            root,
            text=" NIST COMPLIANCE ",
            bg="#2b2b2b",
            fg="white",
            font=("Helvetica", 11, "bold"),
            padx=14,
            pady=12
        )
        nist.grid(row=1, column=2, padx=14, pady=10, sticky="n")

        tk.Label(nist, text="Overall Compliance",
                 fg="#cccccc", bg="#2b2b2b").pack(anchor="w")

        outer = tk.Frame(nist, bg="#444", width=220, height=24, bd=2, relief="ridge")
        outer.pack(pady=6)
        outer.pack_propagate(False)

        tk.Frame(outer, bg="#4caf50", width=190, height=20).place(x=2, y=2)

        tk.Label(
            nist,
            text="90% (NIST-standardized cryptography)",
            fg="#81c784",
            bg="#2b2b2b",
            font=("Helvetica", 10, "bold")
        ).pack(pady=(0, 10))

        # NIST LEVELS
        self._legend_item(nist, "#64b5f6", "CRYSTALS-Kyber : NIST Level 3")
        self._legend_item(nist, "#81c784", "CRYSTALS-Dilithium : NIST Level 3")
        self._legend_item(nist, "#ffd54f", "AES-GCM : NIST Level 5")
        self._legend_item(nist, "#ef9a9a", "Steganography : Auxiliary")

        # ================= STATUS =================
        self.status_label = tk.Label(
            root,
            text="STATUS: SYSTEM READY",
            fg="white",
            bg="#424242",
            font=("Helvetica", 11, "bold"),
            pady=10
        )
        self.status_label.grid(row=2, column=0, columnspan=3, sticky="ew")

        self._show_image("images/Cover.png", self.cover_image_label)

    # ================= HELPERS =================
    def _panel(self, parent, title):
        return tk.LabelFrame(
            parent, text=f" {title} ",
            bg="#2b2b2b",
            fg="white",
            font=("Helvetica", 12, "bold"),
            padx=16, pady=16
        )

    def _step_box(self, parent, title):
        box = tk.LabelFrame(
            parent, text=title,
            bg="#1e1e1e",
            fg="#dddddd",
            font=("Helvetica", 10, "bold"),
            padx=10, pady=8
        )
        box.pack(fill="x", pady=6)
        return box

    def _step_text(self, parent, title, color, disabled):
        box = self._step_box(parent, title)
        txt = tk.Text(
            box,
            height=4,
            width=52,
            bg=color,
            relief="flat",
            state="disabled" if disabled else "normal"
        )
        txt.pack(pady=6)
        return txt

    def _legend_item(self, parent, color, text):
        row = tk.Frame(parent, bg="#2b2b2b")
        row.pack(anchor="w", pady=3)

        tk.Frame(row, bg=color, width=12, height=12).pack(side="left", padx=(0, 6))
        tk.Label(row, text=text,
                 fg="#eeeeee", bg="#2b2b2b",
                 font=("Helvetica", 10)).pack(side="left")

    def _show_image(self, path, label):
        img = Image.open(path).resize((200, 200))
        photo = ImageTk.PhotoImage(img)
        label.image = photo
        label.config(image=photo)

    # ================= LOGIC =================
    def encrypt_and_embed(self):
        msg = self.message_entry.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showerror("Error", "Please enter a message")
            return

        msg_bytes = msg.encode()
        signature = sign_message(self.sign_private_key, msg_bytes)
        ciphertext, _ = encrypt_message(
            self.kem_public_key, msg_bytes, self.sign_private_key
        )

        self.sender_cipher.config(state="normal")
        self.sender_cipher.delete("1.0", tk.END)
        self.sender_cipher.insert(tk.END, base64.b64encode(ciphertext).decode())
        self.sender_cipher.config(state="disabled")

        self.sender_signature.config(state="normal")
        self.sender_signature.delete("1.0", tk.END)
        self.sender_signature.insert(tk.END, base64.b64encode(signature).decode())
        self.sender_signature.config(state="disabled")

        embed_data("images/Cover.png", ciphertext, "images/stego.png")
        self._show_image("images/stego.png", self.stego_image_label)

        self.status_label.config(
            text="STATUS: ENCRYPTION, SIGNING AND EMBEDDING COMPLETE",
            bg="#2e7d32"
        )

    def extract_and_decrypt(self):
        extracted = extract_data("images/stego.png")

        self.receiver_cipher.config(state="normal")
        self.receiver_cipher.delete("1.0", tk.END)
        self.receiver_cipher.insert(tk.END, base64.b64encode(extracted).decode())
        self.receiver_cipher.config(state="disabled")

        plaintext, signature = decrypt_message(
            self.kem_private_key, extracted, self.sign_public_key
        )

        self.receiver_signature.config(state="normal")
        self.receiver_signature.delete("1.0", tk.END)
        self.receiver_signature.insert(tk.END, base64.b64encode(signature).decode())
        self.receiver_signature.config(state="disabled")

        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, plaintext.decode())
        self.output_text.config(state="disabled")

        self.status_label.config(
            text="STATUS: DECRYPTION SUCCESSFUL",
            bg="#2e7d32"
        )


# ================= MAIN =================
if __name__ == "__main__":
    root = tk.Tk()
    PQCStegoUI(root)
    root.mainloop()
