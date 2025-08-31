# Secure Messaging

⚠️ **Disclaimer:** This code should not be used in real-world production environments.  
It is primarily an experimental and educational project, with about 90% of the code generated with AI assistance.  
Bugs, inefficiencies, and security weaknesses may exist.

---

## 📌 Overview

Secure Messaging is an experimental multi-layer encrypted messaging framework.  
It combines several symmetric and asymmetric cryptographic layers, including post-quantum algorithms, to provide enhanced message confidentiality.

The system is designed for research, testing, and educational purposes.

**💡 Contributions Welcome:** This project is open for suggestions, improvements, and fixes.  
If you have ideas or corrections, feel free to submit them — **your contributions are highly appreciated!**

---

## ✨ Features

- 🔑 **Post-Quantum Key Exchange** using Kyber and ECDH — resolves into a 90-byte long hybrid key  
- 🖊️ **Digital Signatures** using Dilithium and Ed25519 — resolves into a hybrid authentication  
- 🔐 **TLS 1.3 authentication**  
- 🔒 **Multiple symmetric encryption layers:**
  - AES (Advanced Encryption Standard)
  - ChaCha20
  - Serpent Cipher
  - OTP (XOR-based one-time pad)  
- 🖥️ Simple GUI interface for sending/receiving messages  
- 📂 Modular encryption layers for experimentation  
- 🖼️ Includes a custom application icon (`lock.ico`)

---

## 🚀 Installation

### Requirements
- **Python 3.11+**  
- Recommended OS: Windows / Linux / macOS  

**💡 Contributions & Fixes:** If you find any issues during installation, feel free to open a pull request or submit a bug report.  
**Your help improves this project!**

---

## Installation

You can either download it from **Releases** or build it yourself using **PyInstaller**.

---

## Setup

- Run the `.exe`. It may take a little time for the application to start and generate all required files.  
  👉 I recommend creating a new folder for it because of the generated config files.  

- This application will require a minimum of **700 MB of disk space**.  

- For the program to work with two peers, they need to share certain files, which either peer must generate.  
  👉 I recommend sharing them only through **physical transfer** (USB stick, cable, etc.), never via network or cloud storage — otherwise, it defeats the whole point of the design.  

- Once the application is running, **close it** and copy the entire folder to the other device using a USB stick.  
  Then copy `my_dilithium_pub.bin` into the other peer’s folder and rename it to `peer_dilithium_pub.bin`.  
  Once this is complete, repeat the same step in reverse for the other peer.  

- Then connect! If everything is done correctly, you should be able to connect after entering the IP and port.  
  👉 I recommend keeping the default port `9000`.  

- Click the **Generate Pad** button and choose the program’s folder as the directory.  

- Try sending a simple message such as `"hi"` or `"hello world"`.  

- On the sender’s side, the program will generate **3 folders**:  
  - `Serpent_keys`  
  - `AES_keys`  
  - `Chacha_keys`  

- You must copy these three folders (without editing them) along with the generated pad into the other peer’s folder.  

- Make sure both peers have their pads loaded.  
  If not, click **Browse** and select the directory manually.  

✅ That’s it! The program will remember everything after setup.  

---

## ⚠️ Notes & Known Issues

- There is a known **GUI bug**: it sometimes displays `"Pad X"` as if not loaded.  
  👉 However, try sending a message anyway — if it works, it’s only a visual bug.  

---

## 📧 Support

If you encounter any problems or have suggestions, please write to:  
📩 **bobberkamamlus@gmail.com**  

Any help, bug reports, code suggestions, or fixes are highly appreciated!  
If you have improvements, feel free to share them — **contributions are always welcome.**
