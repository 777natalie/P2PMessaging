# P2P Secure Messaging Application
## Computer Security Final Project

---

## Project Overview

This project is a secure peer-to-peer messaging application built in Python that allows two users, Alice and Bob, to communicate through encrypted messages over TCP sockets. The system was designed for my Computer Security final project and focuses on implementing real cryptographic concepts covered throughout the course.

The application uses AES-256-CBC encryption, PBKDF2 key derivation, HMAC authentication, random IV generation, and periodic key rotation to create a more secure messaging environment. Both users must enter the same shared password, but the password itself is never directly used as an encryption key.

The project also includes a tkinter graphical user interface that displays sent and received plaintext messages alongside their ciphertext representations to demonstrate the encryption process in real time.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
  - [Technologies Used](#technologies-used)
  - [Running the Application](#running-the-application)
- [Key Features](#key-features)
- [Usage](#usage)
- [How it Works](#how-it-works)
- [Security Design Decisions](#security-design-decisions)
- [Future Improvements](#future-improvements)
- [Notes](#notes)

---

## Project Structure

```bash
CompSecurity_FinalProject/
│
├── alice.py                          # Alice networking/server logic
├── alice_gui.py                      # Alice GUI messenger window
├── bob_gui.py                        # Bob GUI messenger window
├── encryptengine.py                  # Encryption, decryption, HMAC, and key rotation
├── ComputerSecurity_FinalProject.pdf # Full project report with screenshots
├── Project.pdf                       # Original project instructions
├── README.md
└── __pycache__/                      # Ignored Python cache files
---
```
---

## Setup Instructions

### Technologies Used
* **Python 3**
* **tkinter** – graphical user interface
* **socket** – TCP networking
* **threading** – simultaneous send/receive communication
* **cryptography** – AES, PBKDF2, HMAC, padding, and IV generation

### Running the Application
1. **Install dependencies:**
   ```bash
   pip install cryptography
   ```
2. **Start Alice first:**
   ```bash
   python alice_gui.py
   ```
3. **Start Bob second:**
   ```bash
   python bob_gui.py
   ```

> **Note:** Both users must enter the same password in order to derive matching encryption keys and communicate successfully.

---

## Key Features

* **AES-256-CBC Encryption:** Messages are encrypted using AES-256 in CBC mode with PKCS7 padding.
* **PBKDF2 Key Derivation:** The shared password is stretched into secure encryption keys using PBKDF2HMAC with SHA-256 and a random salt.
* **HMAC Authentication:** Each message is authenticated using HMAC-SHA256 to verify message integrity before decryption.
* **Random IV Generation:** A new random IV is generated for every message so identical plaintext messages produce different ciphertext outputs.
* **Key Rotation:** After a fixed number of messages, a new salt and set of keys are generated to reduce long-term key exposure.
* **GUI Messaging Interface:** The tkinter interface displays sent plaintext, received plaintext, ciphertext output, encryption information, and rotation status.

---

## Usage
1. Start Alice first.
2. Start Bob second.
3. Enter the same shared password.
4. Begin sending encrypted messages.

*Messages are encrypted before transmission and authenticated before decryption.*

---

## How it Works

1. **Connection:** Alice starts as the TCP server and Bob connects as the client.
2. **Key Derivation:** Both users derive matching encryption keys using PBKDF2 and a shared salt.
3. **Encryption:** Messages are encrypted using AES-256-CBC.
4. **Authentication:** HMAC-SHA256 verifies integrity before decryption.
5. **Concurrency:** Separate send/receive threads keep communication active simultaneously.
6. **Uniqueness:** Random IVs ensure ciphertext changes even when the same message is sent multiple times.
7. **Rotation:** Keys are periodically rotated after a set number of messages.

---

## Security Design Decisions


| Requirement | Implementation |
| :--- | :--- |
| **Key length ≥ 56 bits** | AES-256 |
| **Password not directly used as key** | PBKDF2HMAC |
| **Message integrity** | HMAC-SHA256 |
| **Different ciphertext each message** | Random IV |
| **Reliable communication** | TCP sockets |
| **Key management** | Periodic key rotation |
| **GUI requirement** | tkinter |

---

## Future Improvements
* Diffie-Hellman key exchange
* Public/private key authentication
* Deployment across real networks instead of localhost
* File transfer support
* Improved GUI styling
* User authentication system
## Team Contributions

| Name            | Contact                   |
| ----------------| --------------------------|
| Natalie Roman   | casandra.n.roman-1@ou.edu |
