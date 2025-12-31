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
        self.root.geometry("1250x800")
        self.root.configure(bg="#1e1e1e")

        # ⭐ IMPORTANT: make grid responsive & centered
        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(1, weight=1)

        # ================= TITLE =================
        tk.Label(
            root,
            text="POST-QUANTUM SECURE STEGANOGRAPHY PIPELINE",
            font=("Helvetica", 18, "bold"),
            fg="#eeeeee",
            bg="#1e1e1e"
        ).grid(row=0, column=0, columnspan=2, pady=18)

        # ================= KEYS =================
        self.kem_public_key, self.kem_private_key = generate_keypair()
        self.sign_public_key, self.sign_private_key = generate_signing_keypair()

        # ================= MAIN CONTAINER =================
        container = tk.Frame(root, bg="#1e1e1e")
        container.grid(row=1, column=0, columnspan=2, sticky="n")

        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)

        # ================= SENDER =================
        sender = tk.LabelFrame(
            container,
            text=" SENDER ",
            font=("Helvetica", 12, "bold"),
            fg="#ffffff",
            bg="#2b2b2b",
            padx=14,
            pady=14
        )
        sender.grid(row=0, column=0, padx=20, pady=10, sticky="n")

        # ---- Step 1 ----
        step1 = self.step_box(sender, "STEP 1: Plaintext Message")
        self.message_entry = tk.Text(
            step1, height=4, width=50,
            bg="#fff6e5", relief="flat"
        )
        self.message_entry.pack(pady=6)

        # ---- Action ----
        tk.Button(
            sender,
            text="Encrypt → Sign → Embed",
            font=("Helvetica", 10, "bold"),
            bg="#3949ab",
            fg="white",
            width=40,
            command=self.encrypt_and_embed
        ).pack(pady=12)

        # ---- Step 2 ----
        step2 = self.step_box(sender, "STEP 2: Encrypted Ciphertext (Base64)")
        self.sender_cipher = tk.Text(
            step2, height=4, width=50,
            bg="#e8f0ff", relief="flat", state="disabled"
        )
        self.sender_cipher.pack(pady=6)

        # ---- Step 3 ----
        step3 = self.step_box(sender, "STEP 3: Digital Signature (Dilithium)")
        self.sender_signature = tk.Text(
            step3, height=4, width=50,
            bg="#e8fff3", relief="flat", state="disabled"
        )
        self.sender_signature.pack(pady=6)

        # ---- Step 4 ----
        step4 = self.step_box(sender, "STEP 4: Cover Image")
        self.cover_image_label = tk.Label(step4, bg="#1e1e1e")
        self.cover_image_label.pack(pady=6)

        # ================= RECEIVER =================
        receiver = tk.LabelFrame(
            container,
            text=" RECEIVER ",
            font=("Helvetica", 12, "bold"),
            fg="#ffffff",
            bg="#2b2b2b",
            padx=14,
            pady=14
        )
        receiver.grid(row=0, column=1, padx=20, pady=10, sticky="n")

        # ---- Step 5 ----
        step5 = self.step_box(receiver, "STEP 5: Received Stego Image")
        self.stego_image_label = tk.Label(step5, bg="#1e1e1e")
        self.stego_image_label.pack(pady=6)

        # ---- Action ----
        tk.Button(
            receiver,
            text="Extract → Decrypt → Verify",
            font=("Helvetica", 10, "bold"),
            bg="#00897b",
            fg="white",
            width=40,
            command=self.extract_and_decrypt
        ).pack(pady=12)

        # ---- Step 6 ----
        step6 = self.step_box(receiver, "STEP 6: Extracted Ciphertext (Base64)")
        self.receiver_cipher = tk.Text(
            step6, height=4, width=50,
            bg="#e8f0ff", relief="flat", state="disabled"
        )
        self.receiver_cipher.pack(pady=6)

        # ---- Step 7 ----
        step7 = self.step_box(receiver, "STEP 7: Recovered Signature")
        self.receiver_signature = tk.Text(
            step7, height=4, width=50,
            bg="#e8fff3", relief="flat", state="disabled"
        )
        self.receiver_signature.pack(pady=6)

        # ---- Step 8 ----
        step8 = self.step_box(receiver, "STEP 8: Decrypted Message")
        self.output_text = tk.Text(
            step8, height=4, width=50,
            bg="#fff6e5", relief="flat", state="disabled"
        )
        self.output_text.pack(pady=6)

        # ================= STATUS =================
        self.status_label = tk.Label(
            root,
            text="STATUS: SYSTEM READY",
            font=("Helvetica", 11, "bold"),
            fg="white",
            bg="#424242",
            pady=10
        )
        self.status_label.grid(row=2, column=0, columnspan=2, sticky="ew")

        # Initial image
        self.show_image("images/Cover.png", self.cover_image_label)

    # ================= STEP BOX =================
    def step_box(self, parent, title):
        box = tk.LabelFrame(
            parent,
            text=title,
            font=("Helvetica", 10, "bold"),
            fg="#dddddd",
            bg="#1e1e1e",
            padx=10,
            pady=8
        )
        box.pack(fill="x", pady=6)
        return box

    # ================= IMAGE =================
    def show_image(self, path, label):
        img = Image.open(path).resize((240, 240))
        photo = ImageTk.PhotoImage(img)
        label.image = photo
        label.config(image=photo)

    # ================= SENDER =================
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
        self.show_image("images/stego.png", self.stego_image_label)

        self.status_label.config(
            text="STATUS: ENCRYPTION, SIGNING, AND EMBEDDING COMPLETE",
            bg="#2e7d32"
        )

    # ================= RECEIVER =================
    def extract_and_decrypt(self):
        try:
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
                text="STATUS: SIGNATURE VERIFIED AND MESSAGE DECRYPTED",
                bg="#2e7d32"
            )

        except Exception:
            self.status_label.config(
                text="STATUS: VERIFICATION FAILED (TAMPERING DETECTED)",
                bg="#c62828"
            )
            messagebox.showerror(
                "Security Error",
                "Signature verification failed. Data may have been tampered."
            )


# ================= MAIN =================
if __name__ == "__main__":
    root = tk.Tk()
    root.lift()
    root.attributes("-topmost", True)
    root.after(300, lambda: root.attributes("-topmost", False))
    PQCStegoUI(root)
    root.mainloop()
