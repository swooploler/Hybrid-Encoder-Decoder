import tkinter as tk
from tkinter import filedialog, messagebox
import keygen
import encrypt
import decrypt
import os

class HybridEncrypterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Encryption Tool")
        self.root.geometry("400x350")
        
        # Key Generation Button
        self.keygen_button = tk.Button(root, text="Generate RSA Key Pair", command=self.generate_keys)
        self.keygen_button.pack(pady=10)
        
        # Encrypt Button
        self.encrypt_button = tk.Button(root, text="Encrypt a File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)
        
        # Decrypt Button
        self.decrypt_button = tk.Button(root, text="Decrypt a File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)

        # Exit Button
        self.exit_button = tk.Button(root, text="Exit", command=root.quit)
        self.exit_button.pack(pady=10)

    def generate_keys(self):
        try:
            keygen.generate_keys()
            messagebox.showinfo("Success", "RSA Key pair generated successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error generating keys: {e}")

    def encrypt_file(self):
        # Ask for the file to encrypt
        file_path = filedialog.askopenfilename(
            title="Select a text file to encrypt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            # Ask where to save the encrypted files
            encrypted_file_path = filedialog.asksaveasfilename(
                title="Save Encrypted File",
                defaultextension=".bin",
                filetypes=[("Encrypted Files", "*.bin"), ("All Files", "*.*")]
            )
            encrypted_key_path = filedialog.asksaveasfilename(
                title="Save Encrypted Key File",
                defaultextension=".bin",
                filetypes=[("Encrypted Key Files", "*.bin"), ("All Files", "*.*")]
            )

            if encrypted_file_path and encrypted_key_path:
                try:
                    # Encrypt the file and save the results
                    encrypt.encrypt_file(file_path, "public_key.pem", encrypted_file_path, encrypted_key_path)
                    messagebox.showinfo("Success", "File encrypted successfully.")
                except Exception as e:
                    messagebox.showerror("Error", f"Error encrypting file: {e}")

    def decrypt_file(self):
        # Ask for the encrypted file
        encrypted_file_path = filedialog.askopenfilename(
            title="Select an encrypted file",
            filetypes=[("Encrypted Files", "*.bin"), ("All Files", "*.*")]
        )
        if encrypted_file_path:
            # Ask for the encrypted key file
            encrypted_key_path = filedialog.askopenfilename(
                title="Select the encrypted key file",
                filetypes=[("Encrypted Key Files", "*.bin"), ("All Files", "*.*")]
            )
            if encrypted_key_path:
                # Ask where to save the decrypted file
                save_decrypted_path = filedialog.asksaveasfilename(
                    title="Save Decrypted File",
                    defaultextension=".txt",
                    filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
                )

                if save_decrypted_path:
                    try:
                        # Decrypt the file and save the result
                        decrypt.decrypt_file(encrypted_file_path, encrypted_key_path, "private_key.pem", save_decrypted_path)
                        messagebox.showinfo("Success", "File decrypted successfully.")
                    except Exception as e:
                        messagebox.showerror("Error", f"Error decrypting file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    gui = HybridEncrypterGUI(root)
    root.mainloop()
