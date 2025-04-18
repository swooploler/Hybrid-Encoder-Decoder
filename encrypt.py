from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import os

def encrypt_file(file_path, public_key_path):
    # Generate AES key (Fernet key)
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)

    # Read file data
    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    # Load RSA public key
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Save encrypted file
    encrypted_file_path = "D:/Coding n shit/Projects/Encryption Tool/Files/encrypted_file.bin"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)

    # Save encrypted AES key
    encrypted_key_path = "D:/Coding n shit/Projects/Encryption Tool/Files/encrypted_key.bin"
    with open(encrypted_key_path, "wb") as f:
        f.write(encrypted_aes_key)

    print(f"🔐 File encrypted and saved in 'D:/Coding n shit/Projects/Encryption Tool/Files/'")
