# Natalie Roman CS 4173-001
# bob - client side
# GUI cited from https://docs.python.org/3/library/tkinter.html
# Socket cited from https://docs.python.org/3/howto/sockets.html

import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
from encryptengine import derive_key, encrypt, decrypt, generate_mac, verify_mac, rotate_key

HOST = '127.0.0.1'
PORT = 65432

# password popup - has to match alice's
popup = tk.Tk()
popup.title("Enter Password")
popup.configure(bg="#ffe4e1")
popup.geometry("320x140")

tk.Label(popup, text="Enter shared password:",
         bg="#ffe4e1", fg="#333",
         font=("Courier", 11)).pack(pady=12)

pw_entry = tk.Entry(popup, show="*", font=("Courier", 11),
                    relief="sunken", bd=2, width=28)
pw_entry.pack()

password = ""

def set_password():
    global password
    password = pw_entry.get()
    popup.destroy()

tk.Button(popup, text="Connect",
          bg="#c2185b", fg="white",
          font=("Courier", 11, "bold"),
          relief="raised", bd=2,
          command=set_password).pack(pady=12)

popup.mainloop()

# derive K1 and K2 from the password
bob_key, bob_salt = derive_key(password)
bob_mac_key, bob_mac_salt = derive_key(password)

# main window
root = tk.Tk()
root.title("Secure Messenger - Bob")
root.configure(bg="#ffe4e1")
root.geometry("650x580")

title = tk.Label(root, text="Bob - Secure Messenger",
                 bg="#c2185b", fg="white",
                 font=("Courier", 14, "bold"), pady=8)
title.pack(fill="x")

info = tk.Label(root, text="AES-256-CBC | HMAC-SHA256 | Key rotates every 50 messages",
                bg="#ffb6c1", fg="#880e4f",
                font=("Courier", 9), pady=4)
info.pack(fill="x")

chat_box = scrolledtext.ScrolledText(root, state="disabled",
                                     bg="#fff0f5", fg="#333333",
                                     font=("Courier", 11),
                                     wrap="word", padx=8, pady=8,
                                     relief="sunken", bd=3)
chat_box.pack(fill="both", expand=True, padx=8, pady=8)

chat_box.tag_config("bob", foreground="#c2185b", font=("Courier", 11, "bold"))
chat_box.tag_config("alice", foreground="#333333", font=("Courier", 11, "bold"))
chat_box.tag_config("cipher", foreground="#aaaaaa", font=("Courier", 9))
chat_box.tag_config("system", foreground="#ff69b4", font=("Courier", 9, "italic"))

bottom = tk.Frame(root, bg="#ffe4e1")
bottom.pack(fill="x", padx=8, pady=(0, 8))

msg_entry = tk.Entry(bottom, font=("Courier", 12),
                     bg="white", fg="#333",
                     relief="sunken", bd=2)
msg_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 6))

send_btn = tk.Button(bottom, text="SEND",
                     bg="#c2185b", fg="white",
                     font=("Courier", 11, "bold"),
                     relief="raised", bd=3, padx=12)
send_btn.pack(side="right")

status = tk.Label(root, text="Connecting to Alice...",
                  bg="#ffb6c1", fg="#888",
                  font=("Courier", 9), pady=3, anchor="w")
status.pack(fill="x")


def show_message(tag, name, message, ciphertext=None):
    chat_box.config(state="normal")
    chat_box.insert("end", name + "\n", tag)
    chat_box.insert("end", "  " + message + "\n")
    if ciphertext:
        chat_box.insert("end", "  ciphertext: " + ciphertext + "\n", "cipher")
    chat_box.insert("end", "\n")
    chat_box.config(state="disabled")
    chat_box.see("end")


def send_message(event=None):
    global bob_key, bob_salt
    msg = msg_entry.get().strip()
    if msg == "":
        return

    msg_entry.delete(0, "end")

    # check if its time to rotate the key
    bob_key, bob_salt = rotate_key(password, bob_key, bob_salt)

    # encrypt then authenticate 
    iv, ciphertext = encrypt(bob_key, msg)
    mac = generate_mac(bob_mac_key, iv + ciphertext)

    # send salt, mac salt, iv, mac, and ciphertext all together
    data = bob_salt + bob_mac_salt + iv + mac + ciphertext
    s.sendall(len(data).to_bytes(4, 'big') + data)

    show_message("bob", "You (Bob):", msg, ciphertext.hex())


def receive_loop():
    while True:
        try:
            original_length = s.recv(4)
            if not original_length:
                break
            length = int.from_bytes(original_length, 'big')
            data = s.recv(length)

            # unpack everything
            a_salt = data[:16]
            a_mac_salt = data[16:32]
            iv = data[32:48]
            mac = data[48:80]
            ciphertext = data[80:]

            # rebuild alices key from her salt
            a_key, _ = derive_key(password, salt=a_salt)
            a_mac_key, _ = derive_key(password, salt=a_mac_salt)

            # always verify mac before decrypting
            if verify_mac(a_mac_key, iv + ciphertext, mac):
                plaintext = decrypt(a_key, iv, ciphertext)
                root.after(0, show_message, "alice", "Alice:", plaintext, ciphertext.hex())
            else:
                root.after(0, show_message, "system", "WARNING:", "MAC failed, message may be tampered")
        except:
            break


# connect to alice
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

msg_entry.bind("<Return>", send_message)
send_btn.config(command=send_message)

status.config(text="Connected to Alice! Connection is encrypted", fg="#c2185b")
show_message("system", "System:", "Connected to Alice! Messages are encrypted")

threading.Thread(target=receive_loop, daemon=True).start()

root.mainloop()