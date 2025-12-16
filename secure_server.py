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
BLOCK_DURATION = 10 # Block for 10 seconds only

USED_NONCES = set() #stores already used nonces to prevent replay attacks
#tracks failed logins per user and IP
LOGIN_ATTEMPTS = defaultdict(int)
FAILED_LOGINS_BY_IP = defaultdict(int)

# Track when users/IPs were last blocked to prevent repeated blocking
LAST_BLOCK_TIME = defaultdict(float)

ATTACK_LOG = "attack.log"
USER_ACTIVITY_LOG = "user_activity.log"

# Track IPs that are blocked
BLOCKED_IPS = set()
# Track users that are blocked
BLOCKED_USERS = set()

def log_attack(message):
    # timestamp the attacks and place into logs
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(f"\033[91m{line}\033[0m")  # Red color for attacks
    #appends log entry to attack.log
    with open(ATTACK_LOG, "a") as f:
        f.write(line + "\n")

def log_user_activity(message):
    # timestamp user activities
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(f"\033[94m{line}\033[0m")  # Blue color for user activity
    #appends log entry to user_activity.log
    with open(USER_ACTIVITY_LOG, "a") as f:
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
    def register_user(self, username, password, ip_address=None):
        if username in self.users:
            return False, "User already exists"
        
        # Check if user is blocked
        if username in BLOCKED_USERS:
            log_attack(f"[BLOCKED REGISTRATION] Blocked user '{username}' attempted to register from {ip_address}")
            return False, "User account is blocked"
        
        # Check if IP is blocked
        if ip_address and ip_address in BLOCKED_IPS:
            log_attack(f"[BLOCKED REGISTRATION] Blocked IP {ip_address} attempted to register user '{username}'")
            return False, "IP address is blocked"
            
        pw_hash = self.hash_password(password)
        self.users[username] = {
            "password_hash": base64.b64encode(pw_hash).decode(),
            "created_at": time.time(),
            "last_login": None,
            "login_count": 0,
            "registered_from_ip": ip_address,
            "is_active": True,
            "blocked_until": None
        }
        self.save_users()
        
        # Log registration
        ip_info = f" from {ip_address}" if ip_address else ""
        log_user_activity(f"[REGISTRATION] User '{username}' registered{ip_info}")
        
        return True, "User registered"

    #checks if username exists and verifies password hash
    def authenticate_user(self, username, password, ip_address=None):
        # Check if user is blocked
        if username in BLOCKED_USERS:
            log_attack(f"[BLOCKED LOGIN] Blocked user '{username}' attempted login from {ip_address}")
            return False, "User account is blocked"
        
        # Check if IP is blocked
        if ip_address and ip_address in BLOCKED_IPS:
            log_attack(f"[BLOCKED LOGIN] Blocked IP {ip_address} attempted login as '{username}'")
            return False, "IP address is blocked"
            
        # Check if user account is temporarily blocked
        if username in self.users and "blocked_until" in self.users[username]:
            blocked_until = self.users[username]["blocked_until"]
            if blocked_until and time.time() < blocked_until:
                remaining = int(blocked_until - time.time())
                log_attack(f"[TEMPORARY BLOCK] User '{username}' is blocked for {remaining} more seconds")
                return False, f"Account temporarily blocked. Try again in {remaining} seconds"
        
        # logging in without the valid credentials
        if username not in self.users:
            return False, "Invalid username"
            
        stored = base64.b64decode(self.users[username]["password_hash"])
        if self.verify_password(stored, password):
            # Update user stats
            self.users[username]["last_login"] = time.time()
            self.users[username]["login_count"] = self.users[username].get("login_count", 0) + 1
            self.users[username]["is_active"] = True
            self.save_users()
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
        #main directory for received files
        self.upload_dir = "secure_uploads"
        os.makedirs(self.upload_dir, exist_ok=True)
        # Track connected users and their IPs
        self.connected_users = {}  # username -> (thread_id, ip_address, login_time, socket)
        # Track thread to user mapping
        self.thread_to_user = {}   # thread_id -> username
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

    # Force logout a user when attack is detected
    def force_logout_user(self, username, reason):
        if username in self.connected_users:
            user_info = self.connected_users[username]
            ip = user_info["ip_address"]
            thread_id = user_info["thread_id"]
            
            # Log the forced logout
            log_attack(f"[FORCED LOGOUT] User '{username}' logged out due to: {reason}")
            log_user_activity(f"[FORCED LOGOUT] User '{username}' from {ip} logged out: {reason}")
            
            # Remove from tracking dictionaries
            if username in self.connected_users:
                del self.connected_users[username]
            if thread_id in self.thread_to_user:
                del self.thread_to_user[thread_id]
            
            # Show updated connected users
            self.show_connected_users()

    # Check if we should block (prevent repeated blocking)
    def should_block_user(self, username):
        current_time = time.time()
        last_blocked = LAST_BLOCK_TIME.get(f"user:{username}", 0)
        
        # If user was blocked recently (within 30 seconds), don't block again
        if current_time - last_blocked < 30:
            return False
            
        LAST_BLOCK_TIME[f"user:{username}"] = current_time
        return True
    
    def should_block_ip(self, ip_address):
        current_time = time.time()
        last_blocked = LAST_BLOCK_TIME.get(f"ip:{ip_address}", 0)
        
        # If IP was blocked recently (within 30 seconds), don't block again
        if current_time - last_blocked < 30:
            return False
            
        LAST_BLOCK_TIME[f"ip:{ip_address}"] = current_time
        return True

    # Block an IP address for 10 seconds only
    def block_ip_address(self, ip_address, reason):
        # Check if we should block (prevent repeated blocking)
        if not self.should_block_ip(ip_address):
            log_attack(f"[BLOCK SKIPPED] IP {ip_address} was recently blocked, skipping additional block")
            return
            
        BLOCKED_IPS.add(ip_address)
        log_attack(f"[IP BLOCKED] IP {ip_address} blocked for {BLOCK_DURATION} seconds: {reason}")
        
        # Force logout any users from this IP
        users_to_logout = []
        for username, info in self.connected_users.items():
            if info["ip_address"] == ip_address:
                users_to_logout.append(username)
        
        for username in users_to_logout:
            self.force_logout_user(username, f"IP {ip_address} blocked: {reason}")
        
        # Schedule IP unblocking after 10 seconds
        threading.Timer(BLOCK_DURATION, self.unblock_ip, args=[ip_address]).start()
    
    # Unblock an IP address
    def unblock_ip(self, ip_address):
        if ip_address in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip_address)
            log_attack(f"[IP UNBLOCKED] IP {ip_address} is now unblocked")
    
    # Block a user for 10 seconds
    def block_user(self, username, reason):
        # Check if we should block (prevent repeated blocking)
        if not self.should_block_user(username):
            log_attack(f"[BLOCK SKIPPED] User '{username}' was recently blocked, skipping additional block")
            return
            
        BLOCKED_USERS.add(username)
        log_attack(f"[USER BLOCKED] User '{username}' blocked for {BLOCK_DURATION} seconds: {reason}")
        
        # Force logout the user if logged in
        if username in self.connected_users:
            self.force_logout_user(username, reason)
        
        # Update user record
        if username in self.auth.users:
            self.auth.users[username]["blocked_until"] = time.time() + BLOCK_DURATION
            self.auth.save_users()
        
        # Schedule user unblocking after 10 seconds
        threading.Timer(BLOCK_DURATION, self.unblock_user, args=[username]).start()
    
    # Unblock a user
    def unblock_user(self, username):
        if username in BLOCKED_USERS:
            BLOCKED_USERS.remove(username)
            log_attack(f"[USER UNBLOCKED] User '{username}' is now unblocked")
            
            # Clear the blocked_until timestamp
            if username in self.auth.users:
                self.auth.users[username]["blocked_until"] = None
                self.auth.save_users()

    #runs in a serperate thread per client
    def handle_client(self, sock, addr):
        user = None
        ip = addr[0]
        thread_id = threading.get_ident()
        
        # Check if IP is blocked before processing
        if ip in BLOCKED_IPS:
            log_attack(f"[BLOCKED CONNECTION] Blocked IP {ip} attempted to connect")
            sock.close()
            return
        
        log_attack(f"[CONNECT] {ip}")
        log_user_activity(f"[CONNECTION] Connection from {ip}")

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
                        
                        # Force logout if user is logged in
                        if user:
                            self.force_logout_user(user, "Malformed packet attack")
                            user = None
                        
                        # Block IP for 10 seconds for malformed packets
                        self.block_ip_address(ip, "Malformed packet attack")
                        
                        sock.send(json.dumps({
                            "success": False,
                            "message": "Malformed request detected"
                        }).encode())
                        sock.close()
                        break

                    action = command.get("action")
                    #authenticate user
                    if action == "login":
                        resp = self.handle_login(command, addr, thread_id, sock)
                        if resp["success"]:
                            user = command.get("username")
                        sock.send(json.dumps(resp).encode())
                    #register user
                    elif action == "register":
                        ok, msg = self.auth.register_user(
                            command.get("username"),
                            command.get("password"),
                            ip_address=ip
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
                    #logout
                    elif action == "logout":
                        if user:
                            self.handle_logout(user, ip, thread_id)
                            user = None
                        sock.send(json.dumps({
                            "success": True,
                            "message": "Logged out successfully"
                        }).encode())
                    #disconnect
                    elif action == "quit":
                        if user:
                            self.handle_logout(user, ip, thread_id)
                            user = None
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
            if user:
                log_user_activity(f"[DISCONNECT ERROR] User '{user}' from {ip}: {e}")

        finally:
            # If user was logged in but didn't explicitly logout
            if user:
                self.handle_logout(user, ip, thread_id)
            
            sock.close()
            log_attack(f"[DISCONNECT] {ip}")
            log_user_activity(f"[DISCONNECTION] Connection closed from {ip}")

    # -------- Login Handler --------
    def handle_login(self, command, addr, thread_id, sock):
        ip = addr[0]
        username = command.get("username")
        password = command.get("password")
        nonce = command.get("nonce")
        timestamp = command.get("timestamp")
        
        # Check if IP is blocked
        if ip in BLOCKED_IPS:
            log_attack(f"[BLOCKED LOGIN ATTEMPT] Blocked IP {ip} attempted login")
            return {"success": False, "message": "IP address is blocked"}
        
        #blocks replay attacks
        if not self.check_replay(nonce, timestamp):
            log_attack(f"[ATTACK][REPLAY] from {ip}")
            
            # Block IP for 10 seconds for replay attacks
            self.block_ip_address(ip, "Replay attack detected")
            
            return {"success": False, "message": "Replay detected"}
        
        #tracks brute force attempts
        LOGIN_ATTEMPTS[username] += 1
        FAILED_LOGINS_BY_IP[ip] += 1

        success, msg = self.auth.authenticate_user(username, password, ip_address=ip)

        if success:
            # Reset counters on successful login
            LOGIN_ATTEMPTS[username] = 0
            FAILED_LOGINS_BY_IP[ip] = 0
            
            # Track connected user
            self.connected_users[username] = {
                "thread_id": thread_id,
                "ip_address": ip,
                "login_time": time.time(),
                "login_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "socket": sock
            }
            self.thread_to_user[thread_id] = username
            
            # Log successful login
            log_user_activity(f"[LOGIN SUCCESS] User '{username}' logged in from {ip}")
            
            # Show connected users
            self.show_connected_users()
            
            return {"success": True, "message": msg}
        
        # Failed login
        log_user_activity(f"[LOGIN FAILED] Failed login attempt for user '{username}' from {ip}")
        
        # Check for brute force attacks - ONLY block if not recently blocked
        if LOGIN_ATTEMPTS[username] >= MAX_ATTEMPTS:
            log_attack(f"[ATTACK][BRUTE FORCE] user={username} ip={ip}")
            
            # Block user for 10 seconds
            self.block_user(username, "Brute force attack detected")

        if FAILED_LOGINS_BY_IP[ip] >= MAX_ATTEMPTS:
            log_attack(f"[ATTACK][BRUTE FORCE][IP] ip={ip}")
            
            # Block IP for 10 seconds
            self.block_ip_address(ip, "Brute force attack from IP")

        return {"success": False, "message": "Invalid credentials"}
    
    # -------- Logout Handler --------
    def handle_logout(self, username, ip, thread_id):
        if username in self.connected_users:
            # Calculate session duration
            login_time = self.connected_users[username]["login_time"]
            session_duration = time.time() - login_time
            hours = int(session_duration // 3600)
            minutes = int((session_duration % 3600) // 60)
            seconds = int(session_duration % 60)
            
            # Log logout
            duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            log_user_activity(f"[LOGOUT] User '{username}' logged out from {ip} (Session: {duration_str})")
            
            # Remove from connected users
            del self.connected_users[username]
            
            # Remove from thread mapping
            if thread_id in self.thread_to_user:
                del self.thread_to_user[thread_id]
            
            # Show updated connected users
            self.show_connected_users()
    
    # -------- Show Connected Users --------
    def show_connected_users(self):
        if self.connected_users:
            print("\n\033[92m=== Currently Connected Users ===\033[0m")
            print(f"{'Username':<15} {'IP Address':<15} {'Login Time':<20}")
            print("-" * 50)
            for username, info in self.connected_users.items():
                print(f"{username:<15} {info['ip_address']:<15} {info['login_timestamp']:<20}")
            print("=" * 50 + "\n")
        else:
            print("\n[INFO] No users currently connected\n")

    # Create user-specific directory
    def get_user_upload_dir(self, username):
        user_dir = os.path.join(self.upload_dir, username)
        os.makedirs(user_dir, exist_ok=True)
        return user_dir

    #file transfer - FIXED VERSION with user folders
    def handle_file_transfer(self, sock, username):
        try:
            print(f"[DEBUG] Starting file transfer with {username}")
            
            # Check if user is still connected (not force logged out)
            if username not in self.connected_users:
                log_attack(f"[TRANSFER BLOCKED] User '{username}' is no longer logged in")
                sock.send(b"FAILED: Not logged in")
                return
            
            # Get user-specific upload directory
            user_upload_dir = self.get_user_upload_dir(username)
            print(f"[DEBUG] User upload directory: {user_upload_dir}")
            
            # Send server public key
            sock.send(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Receive RSA encrypted AES session key
            key_size_bytes = sock.recv(4)
            if not key_size_bytes:
                raise ValueError("Failed to receive key size")
            key_size = int.from_bytes(key_size_bytes, "big")
            print(f"[DEBUG] AES key size: {key_size} bytes")
            
            enc_key = sock.recv(key_size)
            if len(enc_key) != key_size:
                raise ValueError(f"Incomplete AES key: {len(enc_key)}/{key_size}")
            print(f"[DEBUG] Received encrypted AES key: {len(enc_key)} bytes")

            # Decrypt AES key
            aes_key = self.private_key.decrypt(
                enc_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Receive metadata
            meta_len_bytes = sock.recv(4)
            if not meta_len_bytes:
                raise ValueError("Failed to receive metadata length")
            meta_len = int.from_bytes(meta_len_bytes, "big")
            print(f"[DEBUG] Metadata length: {meta_len} bytes")
            
            # Read metadata in chunks if needed
            meta_bytes = b""
            while len(meta_bytes) < meta_len:
                remaining = meta_len - len(meta_bytes)
                chunk = sock.recv(min(4096, remaining))
                if not chunk:
                    raise ValueError(f"Incomplete metadata: {len(meta_bytes)}/{meta_len}")
                meta_bytes += chunk
            
            print(f"[DEBUG] Received metadata: {len(meta_bytes)} bytes")
            
            meta_pkg = json.loads(meta_bytes.decode())
            
            # Decrypt metadata
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
            print(f"[DEBUG] File metadata: {filename}, size: {metadata.get('filesize', 'unknown')}")

            # Send READY signal
            sock.send(b"READY")
            print(f"[DEBUG] Sent READY signal")

            # Receive encrypted file data
            encrypted = b""
            print(f"[DEBUG] Waiting for file data...")
            
            # Set a timeout for file transfer
            sock.settimeout(30)
            
            try:
                while True:
                    hdr = sock.recv(4)
                    if not hdr:
                        print(f"[DEBUG] No more data (empty header)")
                        break
                        
                    chunk_len = int.from_bytes(hdr, "big")
                    if chunk_len == 0:
                        print(f"[DEBUG] Zero-length chunk received, ending transfer")
                        break
                    
                    print(f"[DEBUG] Receiving chunk of {chunk_len} bytes")
                    
                    # Read the chunk
                    chunk = b""
                    while len(chunk) < chunk_len:
                        remaining = chunk_len - len(chunk)
                        packet = sock.recv(min(4096, remaining))
                        if not packet:
                            print(f"[DEBUG] Connection closed mid-chunk")
                            break
                        chunk += packet
                    
                    if len(chunk) != chunk_len:
                        print(f"[DEBUG] Incomplete chunk: {len(chunk)}/{chunk_len}")
                        break
                        
                    encrypted += chunk
                    print(f"[DEBUG] Received chunk, total so far: {len(encrypted)} bytes")
                    
            except socket.timeout:
                print(f"[DEBUG] Timeout while receiving file data")
            except Exception as e:
                print(f"[DEBUG] Error receiving chunks: {e}")
            
            sock.settimeout(300)  # Reset timeout
            
            if not encrypted:
                print(f"[DEBUG] No file data received")
                sock.send(b"FAILED: No data")
                return
            
            print(f"[DEBUG] Total encrypted data received: {len(encrypted)} bytes")
            
            try:
                file_pkg = json.loads(encrypted.decode())
            except json.JSONDecodeError as e:
                print(f"[DEBUG] Failed to parse JSON: {e}")
                print(f"[DEBUG] First 100 chars: {encrypted[:100]}")
                sock.send(b"FAILED: Invalid data format")
                return

            # Decrypt file data
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
            
            print(f"[DEBUG] Decrypted file data: {len(file_data)} bytes")
            
            # Verify integrity
            actual_hash = hashlib.sha256(file_data).hexdigest()
            if actual_hash != expected_hash:
                print(f"[DEBUG] Hash mismatch. Expected: {expected_hash[:16]}..., Got: {actual_hash[:16]}...")
                log_attack(f"[ATTACK][INTEGRITY] from {username}")
                
                # Force logout for integrity violation
                self.force_logout_user(username, "File integrity violation")
                
                sock.send(b"FAILED: Integrity check failed")
                return

            # Save file to user-specific directory
            file_path = os.path.join(user_upload_dir, filename)
            
            # Handle duplicate filenames by adding timestamp
            if os.path.exists(file_path):
                base_name, ext = os.path.splitext(filename)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"{base_name}_{timestamp}{ext}"
                file_path = os.path.join(user_upload_dir, filename)
                print(f"[DEBUG] File renamed to avoid overwrite: {filename}")

            with open(file_path, "wb") as f:
                f.write(file_data)

            # Log file upload
            file_size_mb = len(file_data) / (1024 * 1024)
            log_user_activity(f"[FILE UPLOAD] User '{username}' uploaded '{filename}' ({file_size_mb:.2f} MB) to {user_upload_dir}")

            sock.send(b"SUCCESS")
            print(f"[DEBUG] File '{filename}' saved to {user_upload_dir} ({len(file_data)} bytes)")
            log_attack(f"[INFO] File '{filename}' received from {username} and saved to user directory")

        except Exception as e:
            print(f"[DEBUG] Transfer error: {e}")
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

        print(f"\033[92m[SERVER] Listening on port {self.port}\033[0m")
        print("-" * 80)

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
