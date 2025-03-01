import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
import base64
from cryptography.fernet import Fernet

# ✅ Generate and Store AES Key
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print("🔑 Key generated and saved as 'secret.key'.")

def load_key():
    if not os.path.exists("secret.key"):
        messagebox.showerror("Error", "Encryption key not found! Generate key first.")
        return None
    return open("secret.key", "rb").read()

# ✅ Encrypt and Decrypt Message
def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted_message).decode()

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(base64.urlsafe_b64decode(encrypted_message))
    return decrypted_message.decode()

# ✅ Browse File Function
def browse_file(entry_widget):
    filename = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if filename:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)

# ✅ Encode Message into Image
def encode_image():
    file_path = encode_file_entry.get()
    message = encode_message_entry.get()
    output_filename = encode_output_entry.get()

    if not file_path or not message or not output_filename:
        messagebox.showerror("Error", "All fields are required!")
        return
    
    try:
        img = Image.open(file_path)
        img = img.convert("RGB")  # Convert to RGB to avoid grayscale issues
        pixels = list(img.getdata())

        key = load_key()
        if not key:
            return

        encrypted_message = encrypt_message(message, key)
        binary_message = ''.join(format(ord(i), '08b') for i in encrypted_message) + '1111111111111110'  # End delimiter

        if len(binary_message) > len(pixels) * 3:
            messagebox.showerror("Error", "Message is too large for this image!")
            return

        encoded_pixels = []
        index = 0

        for pixel in pixels:
            r, g, b = pixel[:3]  # Ensure RGB format
            if index < len(binary_message):
                r = (r & 0xFE) | int(binary_message[index])  # Modify LSB
                index += 1
            if index < len(binary_message):
                g = (g & 0xFE) | int(binary_message[index])  # Modify LSB
                index += 1
            if index < len(binary_message):
                b = (b & 0xFE) | int(binary_message[index])  # Modify LSB
                index += 1

            encoded_pixels.append((r, g, b))

        img.putdata(encoded_pixels)  # Flattened list of RGB tuples
        img.save(output_filename)
        messagebox.showinfo("Success", f"Message successfully encoded in {output_filename}!")

    except Exception as e:
        messagebox.showerror("Error", f"Encoding failed: {str(e)}")


# ✅ Decode Message from Image
def decode_image():
    file_path = decode_file_entry.get()

    if not file_path:
        messagebox.showerror("Error", "Please select an image file!")
        return

    try:
        img = Image.open(file_path)
        pixels = list(img.getdata())

        binary_message = ""
        for pixel in pixels:
            r, g, b = pixel[:3]
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)

        end_marker = "1111111111111110"
        end_index = binary_message.find(end_marker)
        if end_index == -1:
            messagebox.showinfo("Check Result", "No hidden message detected in this file.")
            return

        binary_message = binary_message[:end_index]

        # ✅ Ensure valid binary sequence (must be multiple of 8 bits)
        if len(binary_message) % 8 != 0:
            messagebox.showerror("Error", "Decoding Error: Incomplete binary sequence.")
            return

        try:
            decoded_chars = [chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)]
            encrypted_message = "".join(decoded_chars)

            # ✅ Ensure message is a valid base64 string before decryption
            try:
                encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
            except Exception:
                messagebox.showerror("Error", "Decryption failed: The extracted message is not a valid base64 string.")
                return

            key = load_key()
            if not key:
                return

            decrypted_message = decrypt_message(encrypted_message, key)
            if not decrypted_message:
                messagebox.showerror("Error", "Decryption failed: Invalid or corrupted message.")
                return

            messagebox.showinfo("Decoded Message", f"Hidden Message: {decrypted_message}")

        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")

    except Exception as e:
        messagebox.showerror("Error", f"Decoding failed: {str(e)}")


# ✅ Check If an Image Contains a Hidden Message
def check_if_encoded():
    file_path = decode_file_entry.get()

    if not file_path:
        messagebox.showerror("Error", "Please select an image file!")
        return

    try:
        img = Image.open(file_path)
        pixels = list(img.getdata())

        binary_message = ""
        for pixel in pixels:
            r, g, b = pixel[:3]
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)

        end_marker = "1111111111111110"
        end_index = binary_message.find(end_marker)

        if end_index == -1:
            messagebox.showinfo("Check Result", "No hidden message detected in this file.")
        else:
            messagebox.showinfo("Check Result", "This image contains a hidden message!")

    except Exception as e:
        messagebox.showerror("Error", f"Check failed: {str(e)}")

# ✅ GUI Setup
def main_gui():
    global root, encode_file_entry, encode_message_entry, encode_output_entry, decode_file_entry
    root = tk.Tk()
    root.title("Steganography Tool")
    root.state('zoomed')  # Fullscreen mode
    root.configure(bg='#2C3E50')

    tk.Label(root, text="Steganography Tool", font=("Arial", 24, "bold"), bg='#2C3E50', fg='white').pack(pady=20)

    frame = tk.Frame(root, bg='#2C3E50')
    frame.pack()

    encode_frame = tk.Frame(frame, bg='#2C3E50')
    encode_frame.grid(row=0, column=0, padx=50, pady=20)

    tk.Label(encode_frame, text="Encode Message in Image", font=("Arial", 16), bg='#2C3E50', fg='white').pack(pady=10)
    encode_file_entry = tk.Entry(encode_frame, width=50)
    encode_file_entry.pack()
    tk.Button(encode_frame, text="Browse", command=lambda: browse_file(encode_file_entry)).pack(pady=5)

    tk.Label(encode_frame, text="Enter Message to Encode", font=("Arial", 12), bg='#2C3E50', fg='white').pack()
    encode_message_entry = tk.Entry(encode_frame, width=50)
    encode_message_entry.pack()

    tk.Label(encode_frame, text="Output Image Filename", font=("Arial", 12), bg='#2C3E50', fg='white').pack()
    encode_output_entry = tk.Entry(encode_frame, width=50)
    encode_output_entry.pack()

    tk.Button(encode_frame, text="Encode", command=encode_image).pack(pady=10)

    decode_frame = tk.Frame(frame, bg='#2C3E50')
    decode_frame.grid(row=0, column=1, padx=50, pady=20)

    tk.Label(decode_frame, text="Decode Image Message", font=("Arial", 16), bg='#2C3E50', fg='white').pack(pady=10)
    decode_file_entry = tk.Entry(decode_frame, width=50)
    decode_file_entry.pack()
    tk.Button(decode_frame, text="Browse", command=lambda: browse_file(decode_file_entry)).pack(pady=5)

    tk.Button(decode_frame, text="Decode", command=decode_image).pack(pady=10)
    tk.Button(decode_frame, text="Check if Encoded", command=check_if_encoded).pack(pady=10)

    tk.Button(root, text="Exit", command=root.quit, font=("Arial", 14)).pack(pady=20)
    root.mainloop()

generate_key()
main_gui()
