
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

- 🔑 **Post-Quantum Key Exchange** using Kyber and ECDH - will resolve a 90 bytes long hybrid key
- 🖊️ **Digital Signatures** using Dilithium and ed25519 -will resolve a hybrid authicantion
- TLS1.3 authentication
- 🔒 **Multiple symmetric encryption layers:**
  - AES (Advanced Encryption Standard)
  - ChaCha20
  - Serpent Cipher
  - OTP- xor
- 🖥️ Simple GUI interface for sending/receiving messages  
- 📂 Modular encryption layers for experimentation  
- 🖼️ Includes a custom application icon (`lock.ico`)

---

## 🚀 Installation

### Requirements
- **Python 3.11+**  
- Recommended OS: Windows / Linux / macOS  
**💡 Contributions & Fixes:** If you find any issues during installation, feel free to open a pull request or submit a bug report. **Your help improves this project!**

## Installiton 
-You can either install it from relasese or build it with pyinstaller

## Setup:

-- Run the .exe, itt will take a litlle time to the application to start, and generate all its files!
   I recommend making an new folder becouse fo the config files!
-- This application will need a minimum of 700 megabites of space
-- For this to work with two peers they will need to share some files witch either of them needs to generates!
   I recommend sharing them only with phiscal connection (pendrive, cabel, etc..) never in network or cloud becouse it will defeat the whole point of the code
   Once the application is running close it and copy the folder to the other device with a pendrive!
   then the copy the public 
   
