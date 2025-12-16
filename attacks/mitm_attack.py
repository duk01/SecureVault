import socket
import threading

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5000
REAL_SERVER_HOST = "127.0.0.1"
REAL_SERVER_PORT = 6000

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()

def handle_client(client_sock):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))

    threading.Thread(target=forward, args=(client_sock, server_sock)).start()
    threading.Thread(target=forward, args=(server_sock, client_sock)).start()

def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((LISTEN_HOST, LISTEN_PORT))
    listener.listen(5)

    print("[MITM] Listening on port 5000...")

    while True:
        client, addr = listener.accept()
        print(f"[MITM] Intercepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    main()