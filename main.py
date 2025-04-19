import keygen
import encrypt
import decrypt
import os

cwd = os.getcwd ()

def menu():
    print("\nHybrid File Encryption Tool")
    print("1. Generate RSA Key Pair")
    print("2. Encrypt a File")
    print("3. Decrypt a File")
    print("4. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        keygen.generate_keys()
    elif choice == "2":
        file_path = input("Enter path to file: ")
        encrypt.encrypt_file(file_path, "public_key.pem")
    elif choice == "3":
        decrypt.decrypt_file(f"{cwd}/encrypted_file.bin",
                             f"{cwd}/encrypted_key.bin",
                             f"{cwd}/private_key.pem")
    elif choice == "4":
        exit()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    while True:
        menu()
