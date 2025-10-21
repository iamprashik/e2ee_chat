import socket
import threading
import json
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

HOST = '127.0.0.1'
PORT = 65432
session_key = None

def generate_rsa_keys(name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_pub = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pem_priv = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption()).decode()
    with open(f"{name}_private.pem", "w") as f:
        f.write(pem_priv)
    with open(f"{name}_public.pem", "w") as f:
        f.write(pem_pub)
    return pem_pub

def load_private_key(name):
    with open(f"{name}_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(key, ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def rsa_encrypt(public_key_pem, message):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    return public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))

def save_message(ciphertext, plaintext):
    log = {"ciphertext": ciphertext, "plaintext": plaintext}
    if os.path.exists("messages.json"):
        with open("messages.json", "r") as f:
            data = json.load(f)
    else:
        data = []
    data.append(log)
    with open("messages.json", "w") as f:
        json.dump(data, f, indent=2)

def receive_messages(sock, name, private_key):
    global session_key
    while True:
        data = sock.recv(4096)
        if not data:
            break
        try:
            message = json.loads(data.decode())
        except json.JSONDecodeError:
            print("[ERROR] Received invalid JSON.")
            continue

        msg_type = message.get("type")

        if msg_type == "session_key":
            try:
                decrypted_key = rsa_decrypt(private_key, base64.b64decode(message["session_key"]))
                session_key = decrypted_key
                print("[SESSION KEY RECEIVED]")
            except Exception as e:
                print(f"[ERROR] Failed to decrypt session key: {e}")

        elif msg_type == "send":
            ciphertext = message.get("ciphertext")
            if not ciphertext:
                print("[ERROR] No ciphertext found in message.")
                continue
            print(f"[RECEIVED ENCRYPTED] {ciphertext}")
            if session_key is None:
                print("[ERROR] No session key available. Cannot decrypt.")
                continue
            try:
              plaintext = aes_decrypt(session_key, message['ciphertext']).decode("utf-8")
              print(f"[DECRYPTED MESSAGE] {plaintext}")
              save_message(ciphertext, plaintext)
            except Exception as e:
                pass

        else:
            print(f"[WARNING] Unknown message type: {msg_type}")

def auto_send_session_key(sock, name, to):
    global session_key
    session_key_local = os.urandom(32)
    session_key = session_key_local
    with open(f"{to}_public.pem", "r") as f:
        to_pub = f.read()
    encrypted_key = rsa_encrypt(to_pub, session_key_local)
    msg = {"type": "session_key", "from": name, "to": to,
           "session_key": base64.b64encode(encrypted_key).decode()}
    sock.send(json.dumps(msg).encode())

def start_client(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.send(name.encode())

    public_key_pem = generate_rsa_keys(name)
    private_key = load_private_key(name)

    register_msg = {"type": "register", "name": name, "public_key": public_key_pem}
    sock.send(json.dumps(register_msg).encode())

    threading.Thread(target=receive_messages, args=(sock, name, private_key), daemon=True).start()

    if name.lower() == "alice":
        time.sleep(1)
        auto_send_session_key(sock, name, "Bob")
        time.sleep(1)

    print(f"[{name.upper()} READY]")

    while True:
        line = input()
        if ":" not in line:
            continue
        to, plaintext = line.split(":", 1)
        to = to.strip()
        plaintext = plaintext.strip()
        if session_key is None:
            print("[ERROR] No session key available. Cannot send.")
            continue
        ciphertext = aes_encrypt(session_key, plaintext)
        msg = {"type": "send", "from": name, "to": to, "ciphertext": ciphertext}
        sock.send(json.dumps(msg).encode())
        save_message(ciphertext, plaintext)

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--name":
        print("Usage: python client.py --name Alice")
        sys.exit(1)
    username = sys.argv[2]
    start_client(username)