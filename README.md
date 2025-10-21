# 🔐 E2EE Chat — End-to-End Encrypted Messaging System

Author: **Prashik Koirala**  
Project: **e2ee_chat**

A simple end-to-end encrypted chat system built with Python sockets, RSA for secure key exchange, and AES for encrypted messaging. This project demonstrates secure communication between clients with a relay server that never sees the decrypted content.

---

## 📦 Features

- 🔑 RSA public/private key generation per client
- 🔐 AES session key exchange using RSA encryption
- 📤 Encrypted message transmission via server
- 📥 Local decryption by recipient client
- 🧾 Message logging with ciphertext and plaintext
- 🖥️ Terminal-based interface for simplicity and clarity

---

## 🚀 How to Run

### 1. Install Dependencies

Make sure you have Python 3.8+ installed. Then run:

```bash
pip install -r requirements.txt

2. Start the Server
python server.py

3. Start the Clients
Open two terminals:

Terminal 1 (Bob):
python client.py --name Bob

Terminal 2 (Alice):
python client.py --name Alice

4. Send Messages
In Alice’s terminal:
Bob: Hello Bob!

Server receives:
Encrypted message from Alice to Bob.

Bob will see:
[RECEIVED ENCRYPTED] <ciphertext>
[DECRYPTED MESSAGE] Hello Bob!