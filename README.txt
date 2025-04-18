Hybrid File Encryption Tool
Overview
This tool allows you to encrypt and decrypt files using hybrid encryption, combining RSA and AES encryption. You can generate RSA key pairs, encrypt files with AES using the public RSA key, and decrypt them with the private RSA key.

Features
Generate RSA Key Pair: Create a public and private RSA key.

Encrypt Files: Encrypt files using AES, with the AES key encrypted by the RSA public key.

Decrypt Files: Decrypt files using the AES key encrypted with the RSA private key.

Requirements
Python 3.x

cryptography library

tkinter for GUI

To install the required libraries:

nginx
Copy
Edit
pip install cryptography
Usage
Generate RSA Key Pair
Open the tool.

Click Generate RSA Key Pair.

The key pair will be saved in D:/Coding n shit/Projects/Encryption Tool/Files as public_key.pem and private_key.pem.

Encrypt a File
Click Encrypt.

Select a file to encrypt.

The encrypted file and the encrypted AES key will be saved in D:/Coding n shit/Projects/Encryption Tool/Files.

Decrypt a File
Click Decrypt.

Select the encrypted file and the encrypted AES key.

The decrypted file will be saved in D:/Coding n shit/Projects/Encryption Tool/Files.

File Locations
Encrypted files and keys are saved in D:/Coding n shit/Projects/Encryption Tool/Files.

Decrypted files are also saved in the same folder.

Notes
Make sure that the paths are correct and accessible.

Ensure you have permissions to write to the folder D:/Coding n shit/Projects/Encryption Tool/Files.

License
This project is open source and free to use. For any issues or questions, please refer to the GitHub repository.
