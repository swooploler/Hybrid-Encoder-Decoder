from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import os

def decrypt_file(encrypted_file_path, encrypted_key_path, private_key_path):
    try:
        # Load private RSA key
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        print("Private key loaded successfully.")

        # Read encrypted AES key
        with open(encrypted_key_path, 'rb') as f:
            encrypted_key = f.read()
        print("Encrypted AES key loaded successfully.")

        # Decrypt AES key using RSA private key
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print("AES key decrypted successfully.")

        # Initialize the Fernet object with the decrypted AES key
        fernet = Fernet(aes_key)

        # Read encrypted file data
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        print(f"Encrypted file '{encrypted_file_path}' loaded successfully.")

        # Decrypt the file data using Fernet (AES)
        decrypted_data = fernet.decrypt(encrypted_data)

        # Check if decrypted data is not empty
        if not decrypted_data:
            print("❌ Decrypted data is empty!")
            return

        # Define the output directory for decrypted file
        output_dir = r"D:/Coding n shit/Projects/Encryption Tool/Files"  # Destination folder

        # Ensure the directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)  # Create folder if it doesn't exist

        # Define the decrypted file path in the specified directory
        decrypted_file_path = os.path.join(output_dir, "decrypted_result.txt")

        # Save the decrypted data in the specified directory
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        print(f"✅ File decrypted successfully! Saved as '{decrypted_file_path}'.")

    except Exception as e:
        print(f"❌ Decryption failed: {str(e)}")

if __name__ == "__main__":
    # Replace with your actual file paths
    decrypt_file("D:/Coding n shit/Projects/Encryption Tool/encrypted_files/encrypted_file.bin", 
                 "D:/Coding n shit/Projects/Encryption Tool/encrypted_files/encrypted_key.bin", 
                 "D:/Coding n shit/Projects/Encryption Tool/private_key.pem")
