import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import json


class SecureImageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Image System")

        # Variables
        self.image_path = ""
        self.password = tk.StringVar()
        self.password_decrypt = tk.StringVar()

        # Labels
        tk.Label(root, text="Image Encryption", font=("Helvetica", 16)).grid(row=0, columnspan=2, pady=10)

        tk.Label(root, text="Image Path:").grid(row=1, column=0, sticky="e")
        self.image_path_entry = tk.Entry(root, width=30)
        self.image_path_entry.grid(row=1, column=1, padx=5)
        tk.Button(root, text="Browse", command=self.browse_image).grid(row=1, column=2)

        tk.Label(root, text="Password:").grid(row=2, column=0, sticky="e")
        self.password_entry = tk.Entry(root, width=30, show="*", textvariable=self.password)
        self.password_entry.grid(row=2, column=1, padx=5)

        tk.Button(root, text="Encrypt", command=self.encrypt_image).grid(row=3, columnspan=2, pady=10)

        # Decryption Section
        tk.Label(root, text="Image Decryption", font=("Helvetica", 16)).grid(row=4, columnspan=2, pady=10)

        tk.Label(root, text="Image Path:").grid(row=5, column=0, sticky="e")
        self.decrypt_image_path_entry = tk.Entry(root, width=30)
        self.decrypt_image_path_entry.grid(row=5, column=1, padx=5)
        tk.Button(root, text="Browse", command=self.browse_decrypt_image).grid(row=5, column=2)

        tk.Label(root, text="Password:").grid(row=6, column=0, sticky="e")
        self.password_decrypt_entry = tk.Entry(root, width=30, show="*", textvariable=self.password_decrypt)
        self.password_decrypt_entry.grid(row=6, column=1, padx=5)

        tk.Button(root, text="Decrypt", command=self.decrypt_image).grid(row=7, columnspan=2, pady=10)

    def browse_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.bmp")])
        self.image_path_entry.delete(0, tk.END)
        self.image_path_entry.insert(tk.END, self.image_path)

    def browse_decrypt_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.bmp")])
        self.decrypt_image_path_entry.delete(0, tk.END)
        self.decrypt_image_path_entry.insert(tk.END, self.image_path)

    def generate_key(self, password):
        return sha256(password.encode()).digest()

    def encrypt_image(self):
        try:
            image_path = self.image_path_entry.get()
            password = self.password.get()

            key = self.generate_key(password)
            cipher = AES.new(key, AES.MODE_CBC)

            with open(image_path, 'rb') as f:
                plaintext = f.read()

            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.iv + cipher.encrypt(padded_plaintext)

            output_filename = "encrypted_image.png"  # You can change the output filename
            with open(output_filename, 'wb') as f:
                f.write(ciphertext)

            messagebox.showinfo("Success", "Image encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_image(self):
        try:
            image_path = self.decrypt_image_path_entry.get()
            password = self.password_decrypt.get()

            key = self.generate_key(password)

            with open(image_path, 'rb') as f:
                ciphertext = f.read()

            iv = ciphertext[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext[AES.block_size:])
            plaintext = unpad(padded_plaintext, AES.block_size)

            img = Image.open(plaintext)
            img.show()
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureImageApp(root)
    root.mainloop()
