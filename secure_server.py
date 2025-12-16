#!/usr/bin/env python3

import socket, os, sys, base64, json, hashlib, hmac, secrets, threading, time
from collections import defaultdict
from json import JSONDecodeError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TIME_WINDOW = 10 #replay attacks must be within 10 seconds
MAX_ATTEMPTS = 5 #brute force detection threshold

USED_NONCES = set() #stores already used nonces to prevent replay attacks
#tracks failed logins per user and IP
LOGIN_ATTEMPTS = defaultdict(int)
FAILED_LOGINS_BY_IP = defaultdict(int)

ATTACK_LOG = "attack.log"

def log_attack(message):
    # timestamp the attacks and place into logs
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line)
    #appends log entry to attack.log
    with open(ATTACK_LOG, "a") as f:
        f.write(line + "\n")

# authentication process (authentication, registration, password security)
class AuthManager:
    def __init__(self):
        #loads users from disk at startup
        self.users_file = "users.json"
        self.users = self.load_users()

    #reads users.json if it exists
    def load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                return json.load(f)
        return {}

    #writes updated users back to disk
    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    #hashing and salting password (random 256 bit)
    def hash_password(self, password, salt=None):
        if salt is None:
            salt = secrets.token_bytes(32)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000) #slows brute force attacks
        return salt + dk #salt stored together with hash

    #extract salt, recomputes hash, compares securely
    def verify_password(self, stored_hash, password):
        salt = stored_hash[:32]
        stored_key = stored_hash[32:]
        computed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(stored_key, computed) #prevents timing attacks

    #prevents duplicate users, hashes password, stores as Base64 so JSON can handle binary data
    def register_user(self, username, password):
        if username in self.users:
            return False, "User already exists"
        pw_hash = self.hash_password(password)
        self.users[username] = {
            "password_hash": base64.b64encode(pw_hash).decode(),
            "created_at": time.time()
        }
        self.save_users()
        return True, "User registered"

    #checks if username exists and verifies password hash
    def authenticate_user(self, username, password):
        # logging in without the valid credentials
        if username not in self.users:
            return False, "Invalid username"
        stored = base64.b64decode(self.users[username]["password_hash"])
        if self.verify_password(stored, password):
            return True, "Authentication successful"
        return False, "Invalid password"

    def create_admin_user(self):
        #default user in user data if no users exists
        if not self.users:
            self.register_user("admin", "admin123")
            print("[INIT] Default admin created: admin/admin123")

# ---------------- Server ----------------
class SecureFileServer:
    #default port 5000
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        #set up authentication
        self.auth = AuthManager()
        self.auth.create_admin_user()
        #directory for received files
        self.upload_dir = "secure_uploads"
        os.makedirs(self.upload_dir, exist_ok=True)
        #generates RSA key pair
        self.generate_keys()

    def generate_keys(self):
        #2048-bit RSA private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        #saves public key for clients to trust
        with open("server_public_key.pem", "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    #TLS-like handshake
    #prove server identity and prevents MITM
    def server_handshake(self, sock):
        challenge = secrets.token_bytes(16) #random challenge
        payload = {
            "public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "challenge": base64.b64encode(challenge).decode()
        }
        sock.send(json.dumps(payload).encode()) #sends public key + challenge
        #server signs challenge with private key
        signature = self.private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        sock.send(signature) #client verifies using server public key

    #replay detection
    #checks if nonce exists, timestamp is recent, and nonce hasn't been used before
    def check_replay(self, nonce, timestamp):
        if not nonce or not timestamp:
            return False
        if abs(time.time() - timestamp) > TIME_WINDOW:
            return False
        if nonce in USED_NONCES:
            return False
        USED_NONCES.add(nonce) #marks nonce as spent
        return True

    #runs in a serperate thread per client
    def handle_client(self, sock, addr):
        user = None
        ip = addr[0]
        log_attack(f"[CONNECT] {ip}")

        try:
            self.server_handshake(sock) #performs authentication handshake
            sock.settimeout(300) #prevents idle connections forever

            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break

                    try:
                        decoded = data.decode("utf-8")
                        command = json.loads(decoded)
                    #detects malformed packet attacks
                    except (UnicodeDecodeError, JSONDecodeError):
                        log_attack(f"[ATTACK][MALFORMED] from {ip}")
                        sock.send(json.dumps({
                            "success": False,
                            "message": "Malformed request detected"
                        }).encode())
                        continue

                    action = command.get("action")
                    #authenticate user
                    if action == "login":
                        resp = self.handle_login(command, addr)
                        if resp["success"]:
                            user = command.get("username")
                        sock.send(json.dumps(resp).encode())
                    #register user
                    elif action == "register":
                        ok, msg = self.auth.register_user(
                            command.get("username"),
                            command.get("password")
                        )
                        sock.send(json.dumps({
                            "success": ok,
                            "message": msg
                        }).encode())
                    #secure file upload
                    elif action == "transfer":
                        if not user:
                            sock.send(json.dumps({
                                "success": False,
                                "message": "Not authenticated"
                            }).encode())
                            continue
                        sock.send(json.dumps({
                            "success": True,
                            "message": "Ready"
                        }).encode())
                        self.handle_file_transfer(sock, user)
                    #disconnect
                    elif action == "quit":
                        sock.send(json.dumps({
                            "success": True,
                            "message": "Goodbye"
                        }).encode())
                        break

                    else:
                        sock.send(json.dumps({
                            "success": False,
                            "message": "Unknown command"
                        }).encode())

                except socket.timeout:
                    continue

        except Exception as e:
            log_attack(f"[SESSION ERROR] {ip}: {e}")

        finally:
            sock.close()
            log_attack(f"[DISCONNECT] {ip}")

    # -------- Login Handler --------
    def handle_login(self, command, addr):
        ip = addr[0]
        username = command.get("username")
        password = command.get("password")
        nonce = command.get("nonce")
        timestamp = command.get("timestamp")
        #blocks replay attacks
        if not self.check_replay(nonce, timestamp):
            log_attack(f"[ATTACK][REPLAY] from {ip}")
            return {"success": False, "message": "Replay detected"}
        #tracks brute force attempts
        LOGIN_ATTEMPTS[username] += 1
        FAILED_LOGINS_BY_IP[ip] += 1

        success, msg = self.auth.authenticate_user(username, password)

        if success:
            LOGIN_ATTEMPTS[username] = 0
            FAILED_LOGINS_BY_IP[ip] = 0
            return {"success": True, "message": msg}
        #logs brute force attack
        if LOGIN_ATTEMPTS[username] >= MAX_ATTEMPTS:
            log_attack(f"[ATTACK][BRUTE FORCE] user={username} ip={ip}")

        if FAILED_LOGINS_BY_IP[ip] >= MAX_ATTEMPTS:
            log_attack(f"[ATTACK][BRUTE FORCE][IP] ip={ip}")

        return {"success": False, "message": "Invalid credentials"}

    #file transfer
    def handle_file_transfer(self, sock, username):
        try:
            sock.send(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            #RSA decrypts AES session key
            key_size = int.from_bytes(sock.recv(4), "big")
            enc_key = sock.recv(key_size)

            aes_key = self.private_key.decrypt(
                enc_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            meta_len = int.from_bytes(sock.recv(4), "big")
            meta_bytes = sock.recv(meta_len)
            meta_pkg = json.loads(meta_bytes.decode())
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(
                    base64.b64decode(meta_pkg["nonce"]),
                    base64.b64decode(meta_pkg["tag"])
                ),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            metadata = json.loads(
                decryptor.update(base64.b64decode(meta_pkg["ciphertext"])) +
                decryptor.finalize()
            )

            filename = metadata["filename"]
            expected_hash = metadata["hash"]

            sock.send(b"READY")

            encrypted = b""
            while True:
                hdr = sock.recv(4)
                if not hdr:
                    break
                ln = int.from_bytes(hdr, "big")
                encrypted += sock.recv(ln)

            file_pkg = json.loads(encrypted.decode())
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(
                    base64.b64decode(file_pkg["nonce"]),
                    base64.b64decode(file_pkg["tag"])
                ),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            file_data = decryptor.update(
                base64.b64decode(file_pkg["ciphertext"])
            ) + decryptor.finalize()
            #detects tampering
            if hashlib.sha256(file_data).hexdigest() != expected_hash:
                log_attack(f"[ATTACK][INTEGRITY] from {username}")
                sock.send(b"FAILED")
                return

            with open(os.path.join(self.upload_dir, filename), "wb") as f:
                f.write(file_data)

            sock.send(b"SUCCESS")
            log_attack(f"[INFO] File '{filename}' received from {username}")

        except Exception as e:
            log_attack(f"[ATTACK][TRANSFER ERROR] {username}: {e}")
            try:
                sock.send(b"FAILED")
            except:
                pass

    # -------- Start Server --------
    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP socket
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(5) #allows 5 queued connections

        print(f"[SERVER] Listening on port {self.port}")

        while True:
            client, addr = srv.accept()
            threading.Thread(
                target=self.handle_client,
                args=(client, addr),
                daemon=True
            ).start()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000 #optional CLI port, default 5000)
    SecureFileServer(port=port).start() #start server