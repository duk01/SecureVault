import socket
import json
import time

HOST = "127.0.0.1"
PORT = 5000

replayed_packet = {
    "action": "login",
    "username": "admin",
    "password": "admin123"
}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

for i in range(3):
    sock.send(json.dumps(replayed_packet).encode())
    response = sock.recv(4096).decode()
    print(f"[Replay {i}] {response}")
    time.sleep(1)

sock.close()