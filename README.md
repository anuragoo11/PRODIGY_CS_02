# PRODIGY_CS_02
# 🖼️ Image Encryption Tool

This project implements a simple image encryption and decryption tool using Python's tkinter for the GUI and PIL (Pillow) for image manipulation.

## 📖 Overview

The Image Encryption Tool allows users to encrypt and decrypt images using a specified encryption key. Encryption involves applying a mathematical operation to each pixel of the image, while decryption reverses this operation to retrieve the original image.

## 🛠️ Features

- **Select Image:** Allows users to choose an image file (supports .png, .jpg, .jpeg formats).
- **Encryption Key:** Users input an integer key for encryption and decryption.
- **Encrypt Image:** Applies encryption to the selected image and saves the encrypted version.
- **Decrypt Image:** Reverses encryption to retrieve and save the original image.

## 📚 How It Works

The tool uses tkinter for the graphical interface. Upon selecting an image and providing an encryption key:
- **Encrypt:** Adds the key value to each pixel's RGB values modulo 256.
- **Decrypt:** Subtracts the key value from each pixel's RGB values modulo 256.

## 💻 Requirements

- Python 3.x
- tkinter (typically included in standard Python installations)
- Pillow (PIL) library: `pip install pillow`

## 🚀 How to Run

1. **Clone the Repository:**
   sh
   git clone <repository-url>
   cd <repository-directory>
   

2. **Install Dependencies:**
   sh
   pip install pillow
   

3. **Run the Program:**
   sh
   python pixel.py
   

4. **Using the Program:**
   - Click **Select Image** to choose an image file.
   - Enter an integer **Encryption Key**.
   - Click **Encrypt** to encrypt the selected image.
   - Click **Decrypt** to decrypt the previously encrypted image.

## 📂 Project Structure

### File: `pixel.py`

This file contains the main implementation of the Image Encryption Tool using tkinter for GUI and PIL for image processing.

#### Functions

- **select_image():** Opens a file dialog to select an image file.
- **encrypt_image():** Encrypts the selected image using the specified key.
- **decrypt_image():** Decrypts the previously encrypted image using the same key.

#### GUI Components

- **button_select_image:** Button to select an image file.
- **entry_key:** Entry field for the encryption key.
- **button_encrypt:** Button to trigger the encryption process.
- **button_decrypt:** Button to trigger the decryption process.
- **label_image:** Displays the selected image and the decrypted image.

## 🙏 Contributions

Contributions are welcome! If you have any suggestions, find bugs, or want to add features, please open an issue or a pull request on GitHub.

Thank you for using this Image Encryption Tool! Enjoy encrypting and decrypting your images securely.


### How to Add this README.md to Your Repository

1. *Create the README.md File:*
   - Open your text editor or IDE.
   - Create a new file and name it README.md.
   - Copy the above content into the README.md file.
   - Save the file in the same directory as your pixel.py file.

2. *Upload the README.md File to GitHub:*
   - If you're using the GitHub web interface:
     - Go to your repository on GitHub.
     - Click on "Add file" > "Create new file".
     - Name the file README.md.
     - Paste the content from the above template into the editor.
     - Scroll down and click "Commit new file" to save it to the repository.

3. *Using Git Commands to Upload README.md:*
   - If you prefer using Git commands, follow these steps in your terminal:

   sh
   git add README.md
   git commit -m "Added detailed README.md file for Image Encryption Tool"
   git push origin master
