import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from PIL import Image, ImageTk
import os

# Constants
WINDOW_WIDTH = 700
WINDOW_HEIGHT = 500
KEY_LENGTH = 32
SALT_LENGTH = 16
ITERATIONS = 100_000

# Key Derivation Function
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=ITERATIONS)

# Encryption
def encrypt_message(message, password):
    salt = get_random_bytes(SALT_LENGTH)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    result = b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return result

# Decryption
def decrypt_message(encrypted_message, password):
    raw = b64decode(encrypted_message)
    salt = raw[:SALT_LENGTH]
    nonce = raw[SALT_LENGTH:SALT_LENGTH+16]
    tag = raw[SALT_LENGTH+16:SALT_LENGTH+32]
    ciphertext = raw[SALT_LENGTH+32:]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Main Application
def main():
    window = tk.Tk()
    window.title("🔐 AES Encryption Tool")
    window.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    window.resizable(False, False)

    # Load background image
    canvas = tk.Canvas(window, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    bg_photo = None
    try:
        image_path = "bg.png"
        if os.path.exists(image_path):
            bg_image = Image.open(image_path)
            bg_image = bg_image.resize((WINDOW_WIDTH, WINDOW_HEIGHT))
            bg_photo = ImageTk.PhotoImage(bg_image)
            canvas.create_image(0, 0, image=bg_photo, anchor="nw")
    except Exception as e:
        print(f"⚠️ Failed to load background image: {e}")

    # Inner frame background
    frame_bg = tk.Label(canvas, image=bg_photo)
    frame_bg.image = bg_photo
    frame_bg.place(x=0, y=0, relwidth=1, relheight=1)

    frame = tk.Frame(canvas, bg="#1a1a1a")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    # Style settings
    entry_style = {'font': ('Segoe UI', 11), 'bg': '#2e2e2e', 'fg': 'white', 'insertbackground': 'white', 'bd': 1, 'relief': 'solid', 'highlightthickness': 0}
    button_style = {'font': ('Segoe UI', 10, 'bold'), 'bg': '#4a90e2', 'fg': 'white', 'bd': 0, 'activebackground': '#357ABD', 'activeforeground': 'white', 'padx': 10, 'pady': 6}

    # Title
    tk.Label(frame, text="AES Encryption Tool", font=("Segoe UI", 16, "bold"), bg="#1a1a1a", fg="white").pack(pady=(10, 5))

    # Message input
    tk.Label(frame, text="Enter your message:", bg="#1a1a1a", fg="white", anchor="w").pack(fill="x", padx=10)
    message_entry = tk.Text(frame, height=5, width=60, wrap='word', **entry_style)
    message_entry.pack(pady=5, padx=10)

    # Password input
    tk.Label(frame, text="Enter password:", bg="#1a1a1a", fg="white", anchor="w").pack(fill="x", padx=10)
    password_entry = tk.Entry(frame, show="*", width=60, **entry_style)
    password_entry.pack(pady=5, padx=10)

    # Result output
    tk.Label(frame, text="Result:", bg="#1a1a1a", fg="white", anchor="w").pack(fill="x", padx=10)
    result_text = tk.Text(frame, height=4, width=60, wrap='word', **entry_style)
    result_text.pack(pady=5, padx=10)

    # Functions
    def encrypt():
        msg = message_entry.get("1.0", tk.END).strip()
        pwd = password_entry.get().strip()
        if msg and pwd:
            try:
                encrypted = encrypt_message(msg, pwd)
                result_text.delete("1.0", tk.END)
                result_text.insert(tk.END, encrypted)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def decrypt():
        msg = message_entry.get("1.0", tk.END).strip()
        pwd = password_entry.get().strip()
        if msg and pwd:
            try:
                decrypted = decrypt_message(msg, pwd)
                result_text.delete("1.0", tk.END)
                result_text.insert(tk.END, decrypted)
            except Exception as e:
                messagebox.showerror("Decryption Error", str(e))

    def copy_to_clipboard():
        window.clipboard_clear()
        window.clipboard_append(result_text.get("1.0", tk.END))
        messagebox.showinfo("Copied", "Text copied to clipboard!")

    def save_to_file():
        data = result_text.get("1.0", tk.END).strip()
        if data:
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if path:
                with open(path, "w") as file:
                    file.write(data)

    def load_from_file():
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "r") as file:
                content = file.read()
                message_entry.delete("1.0", tk.END)
                message_entry.insert(tk.END, content)

    # Buttons
    button_frame = tk.Frame(frame, bg="#1a1a1a")
    button_frame.pack(pady=15)

    tk.Button(button_frame, text="Encrypt", command=encrypt, **button_style).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Decrypt", command=decrypt, **button_style).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="Copy", command=copy_to_clipboard, **button_style).grid(row=0, column=2, padx=5, pady=5)
    tk.Button(button_frame, text="Save", command=save_to_file, **button_style).grid(row=0, column=3, padx=5, pady=5)
    tk.Button(button_frame, text="Load", command=load_from_file, **button_style).grid(row=0, column=4, padx=5, pady=5)

    window.mainloop()

if __name__ == "__main__":
    main()