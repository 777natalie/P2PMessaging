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

## Team Contributions

| Name            | Contact                   |
| ----------------| --------------------------|
| Natalie Roman   | casandra.n.roman-1@ou.edu |
