#!/usr/bin/env python3
import socket
import os
import sys
import base64
import json
import hashlib
import getpass
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#encapsulates connection, authentication, file encryption, file transfer
class SecureClient:
    def __init__(self, server_host, server_port=5000):
        #stores server connection info
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None #holds TCP packet
        self.username = None #tracks authentication state

    def connect(self):
        try:
            #creates TCP socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #connects to the server
            self.sock.connect((self.server_host, self.server_port))
            #performs TLS-like server authentication
            self.verify_server()
            print(f"Connected to server at {self.server_host}:{self.server_port}")
        #any failure exits
        except Exception as e:
            print(f"Connection failed: {e}")
            sys.exit(1)
    
    #ensures it's the real server, not an MITM attacker
    def verify_server(self):
        #receives server's handshake payload
        data = json.loads(self.sock.recv(4096).decode())
        #extracts server public key and challenge
        public_key_pem = data['public_key'].encode()
        challenge = base64.b64decode(data['challenge'])
        #receives server's RSA signature
        signature = self.sock.recv(256)
        #computes public key fingerprint (log or compare)
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()
        #loads server's public RSA key
        public_key = serialization.load_pem_public_key(public_key_pem)
        #verifies server signed challenge correctly and prevents MITM attacks
        public_key.verify(
            signature,
            challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def send(self, payload):
        #sends a JSON command to the server
        self.sock.send(json.dumps(payload).encode())
        #waits for and parses server's response
        return json.loads(self.sock.recv(4096).decode())

    def login(self):
        #secure password input
        username = input('Username: ').strip()
        password = getpass.getpass('Password: ')
        resp = self.send({
            'action': 'login',
            'username': username,
            'password': password,
            #prevents replay attacks
            'nonce': base64.b64encode(os.urandom(16)).decode(),
            'timestamp': time.time()
        })
        #saves username if authenticated
        if resp.get('success'):
            self.username = username
            print(f"Logged in as {self.username}")
        else:
            print(resp.get('message'))

    def register(self):
        username = input('Username: ').strip()
        password = getpass.getpass('Password: ')
        #prevents user typos
        confirm = getpass.getpass('Confirm Password: ')
        if password != confirm:
            print("Passwords do not match")
            return
        #sends registration request
        resp = self.send({'action': 'register', 'username': username, 'password': password})
        print(resp.get('message'))
        #optionally logs in immediately
        if resp.get('success'):
            login_now = input("Login now? (y/n): ").lower()
            if login_now == 'y':
                self.login()

    #resets authentication state and notifies server
    def logout(self):
        if not self.username:
            print("Not logged in")
            return
        resp = self.send({'action': 'logout'})
        print(resp.get('message'))
        self.username = None

    def send_file(self, file_path):
        #ensures user is authenticated
        if not self.username:
            print("You must be logged in to send files")
            return
        #validates file existence
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        #server must approve transfer
        resp = self.send({'action': 'transfer'})
        if not resp.get('success'):
            print(resp.get('message', 'Cannot start transfer'))
            return

        #receive server public key
        server_pub_pem = b''
        while b'-----END PUBLIC KEY-----' not in server_pub_pem:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Server closed connection while sending public key")
            server_pub_pem += chunk
        #loads server RSA key
        public_key = serialization.load_pem_public_key(server_pub_pem, backend=default_backend())

        #read file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        filename = os.path.basename(file_path)
        filesize = len(file_data)

        print(f"Sending file: {filename} ({self._format_size(filesize)})")

        #generate random  256 bit AES key and encrypt with RSA
        aes_key = os.urandom(32)
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        #length prefix framing
        self.sock.send(len(encrypted_aes_key).to_bytes(4, 'big'))
        self.sock.send(encrypted_aes_key)

        #encrypt and send metadata
        metadata = {
            'username': self.username,
            'filename': filename,
            'filesize': filesize,
            'hash': hashlib.sha256(file_data).hexdigest() #SHA-256 hash
        }
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json.dumps(metadata).encode()) + encryptor.finalize()
        encrypted_meta = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
        meta_bytes = json.dumps(encrypted_meta).encode()
        self.sock.send(len(meta_bytes).to_bytes(4, 'big'))
        self.sock.send(meta_bytes)

        ready = self.sock.recv(1024)
        #ensures protocol synchronization
        if ready.strip() != b"READY":
            print("Server not ready")
            return

        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        encrypted_package = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
        encrypted_bytes = json.dumps(encrypted_package).encode()

        chunk_size = 4096
        sent = 0
        #sends file in chunks
        for i in range(0, len(encrypted_bytes), chunk_size):
            chunk = encrypted_bytes[i:i + chunk_size]
            self.sock.send(len(chunk).to_bytes(4, 'big')) #length-prefixed framing
            self.sock.send(chunk)
            sent += len(chunk)
            #displays progress bar
            print(f"\rProgress: {sent / len(encrypted_bytes) * 100:.1f}%", end='')
        print()

        resp = self.sock.recv(1024)
        #confirms successful transfer
        if resp.strip() == b"SUCCESS":
            print("File sent successfully")
        else:
            print(f"File transfer failed: {resp.decode()}")

    def quit(self):
        if self.sock:
            try:
                self.send({'action': 'quit'})
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        print("Goodbye!")

    def main_menu(self):
        self.connect()
        while True:
            print("\n=== Secure File Transfer Menu ===")
            if self.username:
                print(f"Logged in as: {self.username}")
                print("1) Send File")
                print("2) Logout")
                print("3) Quit")
            else:
                print("1) Login")
                print("2) Register")
                print("3) Quit")
            choice = input("> ").strip()
            if self.username:
                if choice == '1':
                    file_path = input("Enter file path: ").strip()
                    if file_path:
                        self.send_file(file_path)
                elif choice == '2':
                    self.logout()
                elif choice == '3':
                    self.quit()
                    break
            else:
                if choice == '1':
                    self.login()
                elif choice == '2':
                    self.register()
                elif choice == '3':
                    self.quit()
                    break

    def _format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}GB"

def main():
    if len(sys.argv) < 2:
        print("Usage: python secure_client.py <server_ip> [port]")
        sys.exit(1)
    #command line server configuration
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    client = SecureClient(host, port)
    client.main_menu() #starts interactive client

if __name__ == '__main__':
    main()