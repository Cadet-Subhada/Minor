# Quantum-Safe Cryptography with Steganography

## 📌 Overview

This project implements a **secure communication system** using **post-quantum cryptography** combined with **image steganography**. It ensures confidentiality, integrity, and covert transmission of data.

The system encrypts a message using quantum-safe algorithms, embeds it into an image, and allows secure extraction and decryption at the receiver’s end.

---

## 🚀 Features

* 🔐 Post-Quantum Key Exchange using **Kyber**
* ✍️ Digital Signature using **Dilithium**
* 🔒 Symmetric Encryption using **AES-GCM**
* 🖼️ Data hiding using **LSB Steganography**
* 🔁 End-to-end secure pipeline
* 🧪 Test module for validation
* 🖥️ Optional UI for demonstration

---

## 🧠 System Workflow

Message → Encrypt → Sign → Embed → Extract → Verify → Decrypt → Original Message

---

## 🛠️ Technologies Used

* Python
* Open Quantum Safe (liboqs)
* NumPy
* Pillow (PIL)
* Tkinter (UI)

---

## 📂 Project Structure

```
Project/
├── crypto/        # Encryption, decryption, keygen, signatures
├── stego/         # LSB embedding and extraction
├── images/        # Cover and stego images
├── main.py        # Core pipeline execution
├── ui.py          # Graphical interface
├── test_oqs.py    # OQS test script
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the repository

```
git clone https://github.com/Cadet-Subhada/Minor.git
cd Minor
```

### 2️⃣ Create virtual environment

```
python3 -m venv venv
source venv/bin/activate
```

### 3️⃣ Install dependencies

```
pip install -r requirements.txt
```

---

## ⚠️ Important: Install Open Quantum Safe (OQS)

This project requires `liboqs`:

```
sudo apt install cmake ninja-build build-essential git python3-dev -y

git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake -GNinja ..
ninja
sudo ninja install
```

Then install Python bindings:

```
pip install git+https://github.com/open-quantum-safe/liboqs-python.git
```

---

## ▶️ How to Run

### Run main pipeline

```
python main.py
```

### Run UI (optional)

```
python ui.py
```

### Test OQS

```
python test_oqs.py
```

---

## 📊 Sample Output

```
--- KEY GENERATION ---
--- ENCRYPTION ---
Ciphertext length: 3244
--- STEGANOGRAPHY EMBED ---
--- STEGANOGRAPHY EXTRACT ---
--- DECRYPTION ---
--- RESULT ---
Decrypted message: b'HELLO POST QUANTUM WORLD'
Shared secret match: True
```

---

## 🔐 Security Components

| Component         | Purpose                     |
| ----------------- | --------------------------- |
| Kyber             | Quantum-safe key exchange   |
| Dilithium         | Digital signature           |
| AES-GCM           | Confidentiality + integrity |
| LSB Steganography | Covert communication        |

---

## 🎯 Applications

* Secure communication systems
* Military and defense communication
* Confidential data transmission
* Stealth data embedding

---

## 📌 Future Improvements

* Enhanced GUI
* Performance benchmarking
* Support for larger payloads
* Network-based communication

---

## 👩‍💻 Author

**Subhada Mallick**

---

## 📜 License

This project is for academic purposes.
