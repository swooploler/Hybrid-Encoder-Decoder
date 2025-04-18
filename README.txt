# Hybrid File Encryption Tool

A command-line based file encryption and decryption tool using **Hybrid Cryptography (AES + RSA)**.  
The system combines the speed of symmetric encryption (AES) with the security of asymmetric encryption (RSA) to ensure safe file transfers and storage.

---

## Features

- Generate secure RSA key pairs (2048-bit)
- Encrypt any file using AES (Fernet) and encrypt the AES key using RSA
- Decrypt the AES key with RSA and restore the original file
- Simple CLI-based interaction
- Cross-platform (runs on any system with Python)

---

## 🛠️ How It Works

1. **RSA Key Generation**
   - `private_key.pem`: Used for decryption
   - `public_key.pem`: Used for encrypting the AES key

2. **Hybrid Encryption**
   - A random AES key is generated for each file
   - File is encrypted using AES
   - The AES key is encrypted using the RSA public key

3. **Hybrid Decryption**
   - AES key is decrypted using the RSA private key
   - File is decrypted using the decrypted AES key

---
