# Natalie Roman CS 4173-001
# Alice = server side of the P2P messenger
# Socket implementation cited from https://docs.python.org/3/howto/sockets.html

import socket
import threading
from encryptengine import derive_key, encrypt, decrypt, generate_mac, verify_mac, rotate_key

HOST = '127.0.0.1'  # localhost for testing; change to actual IP for real use
PORT = 65432        

password = "TheLastProjectMuahahaha"

# derive K1 and K2 from shared password
alice_key, alice_salt = derive_key(password)
alice_mac_key, alice_mac_salt = derive_key(password)

# send K1 and K2 salts to Bob so he can derive same keys
def send_messages(conn):
    global alice_key, alice_salt
    while True:
        msg = input("Alice: ")
        if msg.lower() == "quit":
            break

        # rotate key if needed before sending
        alice_key, alice_salt = rotate_key(password, alice_key, alice_salt)

        # encrypt then authenticate 
        iv, ciphertext = encrypt(alice_key, msg)
        mac = generate_mac(alice_mac_key, iv + ciphertext)

        # send salt so Bob can derive same key
        # format: salt|mac_salt|iv|mac|ciphertext, all sent as bytes
        data = alice_salt + alice_mac_salt + iv + mac + ciphertext
        conn.sendall(len(data).to_bytes(4, 'big') + data)
        print("Sent ciphertext:", ciphertext.hex())


def receive_messages(conn, bob_key, bob_mac_key):
    while True:
        # read message length first, docs say messages must indicate their length
        original_length = conn.recv(4)
        if not original_length:
            break
        msg_len = int.from_bytes(original_length, 'big')
        data = conn.recv(msg_len)

        # unpack, salt(16) + mac_salt(16) + iv(16) + mac(32) + ciphertext(rest)
        bob_salt = data[:16]
        bob_mac_salt = data[16:32]
        iv = data[32:48]
        mac = data[48:80]
        ciphertext = data[80:]

        # re-derive Bob's key from received salt
        bob_key, _ = derive_key(password, salt=bob_salt)
        bob_mac_key, _ = derive_key(password, salt=bob_mac_salt)

        # verify MAC before decrypting
        if verify_mac(bob_mac_key, iv + ciphertext, mac):
            plaintext = decrypt(bob_key, iv, ciphertext)
            print("\nReceived ciphertext:", ciphertext.hex())
            print("Bob:", plaintext)
        else:
            print("MAC verification failed: message may be tampered")

# cited from https://docs.python.org/3/howto/sockets.html
# "the server socket listens, then accept() produces a client socket for the conversation"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Alice waiting for Bob on {HOST}:{PORT}...")
    conn, addr = server.accept()
    print(f"Bob connected from {addr}")

    with conn:
        bob_key, _ = derive_key(password, salt=alice_salt)
        bob_mac_key, _ = derive_key(password, salt=alice_mac_salt)

        # two threads: one to send, one to receive at same time
        t1 = threading.Thread(target=send_messages, args=(conn,))
        t2 = threading.Thread(target=receive_messages, args=(conn, bob_key, bob_mac_key))
        t1.start()
        t2.start()
        t1.join()
        t2.join()