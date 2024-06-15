import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np


class ImageEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool")

        self.input_image_path = ""
        self.output_encrypted_path = ""
        self.output_decrypted_path = ""
        self.encryption_key = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Frame for file selection and encryption key
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        # Select Image Button
        button_select_image = ttk.Button(frame, text="Select Image", command=self.select_image)
        button_select_image.grid(row=0, column=0, padx=10, pady=10)

        # Encryption Key Entry
        ttk.Label(frame, text="Encryption Key:").grid(row=1, column=0, padx=10, sticky=tk.W)
        entry_key = ttk.Entry(frame, textvariable=self.encryption_key, width=20)
        entry_key.grid(row=1, column=1, padx=10, pady=10)

        # Encrypt Button
        button_encrypt = ttk.Button(frame, text="Encrypt", command=self.encrypt_image)
        button_encrypt.grid(row=2, column=0, padx=10, pady=10)

        # Decrypt Button
        button_decrypt = ttk.Button(frame, text="Decrypt", command=self.decrypt_image)
        button_decrypt.grid(row=2, column=1, padx=10, pady=10)

        # Image Display
        self.label_image = ttk.Label(frame)
        self.label_image.grid(row=3, column=0, columnspan=2, pady=10)

    def select_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", ".png;.jpg;*.jpeg")])
        if file_path:
            self.input_image_path = file_path
            self.output_encrypted_path = file_path[:-4] + "_encrypted.png"
            self.output_decrypted_path = file_path[:-4] + "_decrypted.png"
            image = Image.open(file_path)
            image.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(image)
            self.label_image.config(image=photo)
            self.label_image.image = photo  # keep a reference
        else:
            messagebox.showwarning("Warning", "No image selected.")

    def encrypt_image(self):
        try:
            key = int(self.encryption_key.get())
            image = Image.open(self.input_image_path)
            pixels = np.array(image)
            encrypted_pixels = (pixels + key) % 256
            encrypted_image = Image.fromarray(encrypted_pixels.astype('uint8'))
            encrypted_image.save(self.output_encrypted_path)
            messagebox.showinfo("Encryption Success", f"Encrypted image saved as {self.output_encrypted_path}")
        except ValueError:
            messagebox.showerror("Error", "Encryption key must be an integer.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt image: {str(e)}")

    def decrypt_image(self):
        try:
            key = int(self.encryption_key.get())
            image = Image.open(self.output_encrypted_path)
            pixels = np.array(image)
            decrypted_pixels = (pixels - key) % 256
            decrypted_image = Image.fromarray(decrypted_pixels.astype('uint8'))
            decrypted_image.save(self.output_decrypted_path)
            messagebox.showinfo("Decryption Success", f"Decrypted image saved as {self.output_decrypted_path}")
        except ValueError:
            messagebox.showerror("Error", "Decryption key must be an integer.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt image: {str(e)}")


def main():
    root = tk.Tk()
    app = ImageEncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()