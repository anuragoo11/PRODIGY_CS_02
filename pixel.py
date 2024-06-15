import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryptor")

        # Variables
        self.image_path = None

        # Create GUI elements
        self.label = tk.Label(root, text="Select a .jpg image to encrypt or decrypt:")
        self.label.pack(pady=10)

        self.load_button = tk.Button(root, text="Load Image", command=self.load_image)
        self.load_button.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt Image", command=self.encrypt_image)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(root, text="Decrypt Image", command=self.decrypt_image)
        self.decrypt_button.pack()

        self.image_label = tk.Label(root)
        self.image_label.pack(pady=10)

    def load_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("JPEG files", "*.jpg")])
        if self.image_path:
            image = Image.open(self.image_path)
            image.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(image)
            self.image_label.config(image=photo)
            self.image_label.image = photo
        else:
            messagebox.showerror("Error", "No .jpg image selected.")

    def encrypt_image(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image loaded.")
            return

        image = Image.open(self.image_path)
        encrypted_image = image.point(lambda p: p ^ 255)  # XOR with 255 for encryption
        save_path = os.path.join(os.path.expanduser("~"), "Desktop", "encrypted_image.jpg")
        encrypted_image.save(save_path)
        messagebox.showinfo("Encryption", f"Image encrypted and saved as {save_path}.")

    def decrypt_image(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image loaded.")
            return

        image = Image.open(self.image_path)
        decrypted_image = image.point(lambda p: p ^ 255)  # XOR with 255 for decryption
        save_path = os.path.join(os.path.expanduser("~"), "Desktop", "decrypted_image.jpg")
        decrypted_image.save(save_path)
        messagebox.showinfo("Decryption", f"Image decrypted and saved as {save_path}.")

def main():
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()