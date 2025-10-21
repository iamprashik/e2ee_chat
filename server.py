import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 65432

clients = {}
public_keys = {}

def handle_client(conn, addr):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            message = json.loads(data.decode())
            if message['type'] == 'register':
                public_keys[message['name']] = message['public_key']
                print(f"[REGISTER] {message['name']} registered.")
            elif message['type'] == 'send':
                print(f"[ENCRYPTED MESSAGE] From {message['from']} to {message['to']}: {message['ciphertext']}")
                if message['to'] in clients:
                    clients[message['to']].send(data)
            elif message['type'] == 'session_key':
                if message['to'] in clients:
                    clients[message['to']].send(data)
        except:
            break
    conn.close()

def start_server():
    print("[SERVER STARTED]")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            name = conn.recv(1024).decode()
            clients[name] = conn
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
