import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.fernet import Fernet
import os

cwd = os.getcwd ()
# Function to style buttons
def style_widget(widget):
    font = ('Courier', 14, 'bold')
    widget.configure(bg="black", fg="lime", font=font, highlightbackground="lime")


# Function to generate RSA keys and save them
def generate_rsa_keys():
    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Save private key
        private_key_path = os.path.join(cwd, "private_key.pem")
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        public_key_path = os.path.join(cwd, "public_key.pem")
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        messagebox.showinfo("Success", f"RSA keys generated and saved in {cwd}")
    except Exception as e:
        messagebox.showerror("Error", f"RSA Key generation failed: {str(e)}")


# Function to encrypt the file
def encrypt_file():
    # Select file to encrypt
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not file_path:
        return

    # Select the public key for encryption
    public_key_path = filedialog.askopenfilename(title="Select the public key", filetypes=(("PEM files", "*.pem"),))
    if not public_key_path:
        return

    try:
        # Encrypt the file
        aes_key = Fernet.generate_key()
        fernet = Fernet(aes_key)

        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = fernet.encrypt(data)

        # Load RSA public key
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Encrypt the AES key using RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Define save path
        output_dir = cwd
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save encrypted file
        encrypted_file_path = os.path.join(output_dir, "encrypted_file.bin")
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)

        # Save encrypted AES key
        encrypted_key_path = os.path.join(output_dir, "encrypted_key.bin")
        with open(encrypted_key_path, "wb") as f:
            f.write(encrypted_aes_key)

        messagebox.showinfo("Success", f"File encrypted and saved at {output_dir}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


# Function to decrypt the file
def decrypt_file():
    # Select the encrypted file
    encrypted_file_path = filedialog.askopenfilename(title="Select the encrypted file", filetypes=(("BIN files", "*.bin"),))
    if not encrypted_file_path:
        return

    # Select the encrypted AES key
    encrypted_key_path = filedialog.askopenfilename(title="Select the encrypted AES key", filetypes=(("BIN files", "*.bin"),))
    if not encrypted_key_path:
        return

    # Select the private key
    private_key_path = filedialog.askopenfilename(title="Select the private key", filetypes=(("PEM files", "*.pem"),))
    if not private_key_path:
        return

    try:
        # Load private RSA key
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Load encrypted AES key
        with open(encrypted_key_path, 'rb') as f:
            encrypted_key = f.read()

        # Decrypt AES key using RSA
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Initialize Fernet object with decrypted AES key
        fernet = Fernet(aes_key)

        # Read encrypted file data
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)

        # Define the output directory for the decrypted file
        output_dir = cwd
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save the decrypted data
        decrypted_file_path = os.path.join(output_dir, "decrypted_result.txt")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted and saved at {output_dir}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")


# Create the main window
root = tk.Tk()
root.title("Encryption & Decryption Tool")
root.geometry("500x400")
root.config(bg="black")

# Style the window
title_label = tk.Label(root, text="Encryption & Decryption Tool", fg="lime", bg="black", font=("Courier", 20, 'bold'))
title_label.pack(pady=20)

# Encrypt button
encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_file, width=20)
encrypt_button.pack(pady=10)
style_widget(encrypt_button)

# Decrypt button
decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file, width=20)
decrypt_button.pack(pady=10)
style_widget(decrypt_button)

# Generate RSA Keys button
generate_keys_button = tk.Button(root, text="Generate RSA Keys", command=generate_rsa_keys, width=20)
generate_keys_button.pack(pady=10)
style_widget(generate_keys_button)

# Start the GUI event loop
root.mainloop()
