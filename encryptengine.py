# Natalie Roman CS 4173-001

import os
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# derive a key from the password and salt using PBKDF2
# cant use password directly as key, PBKDF2 stretches into 256 bit key, harder to attack.
# cited from https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/ 

def derive_key(password: str, salt: bytes = None):
    salt_length = 16
    iterations = 1_200_000
    key_length = 32
    
    if salt is None:
        # randomly generate salt if not given
        salt = os.urandom(salt_length)
    
    # derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )

    key = kdf.derive(password.encode())
    return key, salt

# AES-CBC encryption with random IV
# "What will be used for padding?" 
def encrypt(key: bytes, plaintext: str):
    # the random iv solves the same message issue, make sure there is unque ciphertext each time, even with same key and plaintext.
    # cited from https://cryptography.io/en/latest/hazmat/primitives/padding/
    iv = os.urandom(16) # AES block size

    global block_size
    block_size = 128 # AES block size in bits
    padder = padding.PKCS7(block_size).padder() 
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext 

# cited from https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
def decrypt(key:bytes, iv:bytes, ciphertext: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    global block_size
    block_size = 128 # AES block size in bits
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# lecture 8: Encrypt-then-Authenticate: MAC is computed over the ciphertext not the plaintext
# K2 is a separate key from K1 (encryption key) — lecture says we need two keys
# cited from https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/

def generate_mac(mac_key: bytes, ciphertext: bytes):
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    mac = h.finalize()
    return mac

def verify_mac(mac_key: bytes, ciphertext: bytes, mac: bytes):
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    try:
        h.verify(mac)
        return True
    except InvalidSignature:
        return False

# now adding key rotation 
rotation = 50  # rotate every 50 messages
message_count = 0

def rotate_key(password: str, current_key: bytes, current_salt: bytes):
    global message_count
    message_count += 1
    print(f"Message count: {message_count}/{rotation}")

    if message_count >= rotation:
        message_count = 0

        new_key, new_salt = derive_key(password)
        print("Key rotated! New salt generated and new key derived")

        return new_key, new_salt
    return current_key, current_salt

if __name__ == "__main__":
    password = "TheLastProjectMuahahaha"
    
    # K1
    alice_key, alice_salt = derive_key(password)
    bob_key, bob_salt = derive_key(password, salt=alice_salt)

    # K2
    alice_key_mac, alice_salt_mac = derive_key(password)
    bob_key_mac, bob_salt_mac = derive_key(password, salt=alice_salt_mac)

    print("Alice's key:", alice_key.hex())
    print("Bob's key:", bob_key.hex())

    print("Keys match: ", alice_key == bob_key)
    print("MAC keys match:", alice_key_mac == bob_key_mac)
    print()

    # check rotation before sending: counter goes up by 1 each message
    alice_key, alice_salt = rotate_key(password, alice_key, alice_salt)
    bob_key, bob_salt = derive_key(password, salt=alice_salt)

    # encrpy then authenticate for alice
    iv, ciphertext = encrypt(alice_key, "I hope he gives me a 100%")
    mac = generate_mac(alice_key_mac, iv + ciphertext)
    print("Ciphertext:", ciphertext.hex())
    print("MAC:", mac.hex())
    print()

    # bob verifies the mac before decryption
    mac_verified = verify_mac(bob_key_mac, iv + ciphertext, mac)
    print("MAC verified:", mac_verified)

    if mac_verified:
        plaintext = decrypt(bob_key, iv, ciphertext)
        print("Decrypted plaintext:", plaintext)
        print()
    else:
        print("MAC verification failed. Message may have been tampered with.")
        print()

    alice_key, alice_salt = rotate_key(password, alice_key, alice_salt)
    bob_key, bob_salt = derive_key(password, salt=alice_salt)

    iv2, ciphertext2 = encrypt(alice_key, "I hope he gives me a 100%")
    print("Ciphertext 2:", ciphertext2.hex())
    plaintext2 = decrypt(bob_key, iv2, ciphertext2)
    print("Decrypted plaintext 2:", plaintext2)
    print("Same message, different ciphertext?", ciphertext != ciphertext2)