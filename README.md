# Hybrid File Encryption Tool

## Overview
This tool allows you to encrypt and decrypt files using hybrid encryption, combining RSA and AES encryption. You can generate RSA key pairs, encrypt files with AES using the public RSA key, and decrypt them with the private RSA key.

**Caution:** Turn off antivirus while downloading the repository.

## Features
- **Generate RSA Key Pair:** Create a public and private RSA key.
- **Encrypt Files:** Encrypt files using AES, with the AES key encrypted by the RSA public key.
- **Decrypt Files:** Decrypt files using the AES key encrypted with the RSA private key.

## Requirements
- Python 3.x
- `cryptography` library
- `tkinter` for GUI

### To install the required libraries:

- pip install cryptography

## Usage

### Generate RSA Key Pair
1. Open the tool.
2. Click **Generate RSA Key Pair**.
3. The key pair will be saved in the current working directory as `public_key.pem` and `private_key.pem`.

### Encrypt a File
1. Click **Encrypt**.
2. Select a file to encrypt.
3. The encrypted file and the encrypted AES key will be saved in the current working directory.

### Decrypt a File
1. Click **Decrypt**.
2. Select the encrypted file and the encrypted AES key.
3. The decrypted file will be saved in the current working directory.

## File Locations
- Encrypted files and keys are saved in the current working directory.
- Decrypted files are also saved in the same folder.

## Notes
- Make sure that the paths are correct and accessible.
- Ensure you have permissions to write to  the current working directory.

## License
This project is open source and free to use. For any issues or questions, please refer to the GitHub repository.