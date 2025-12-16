import os
import base64
import json
import sys

def main():
    if len(sys.argv) < 2:
        print("Follow README.txt file")
        return

    command = sys.argv[1] #reads first command line arg
    #runs RSA key generation
    if command == "genkeys":
        generate_keys()
    #encrypts file using hybrid encryption
    elif command == "encrypt":
        #ensures required arguments are present
        if len(sys.argv) < 4:
            print("Usage: python hybrid.py encrypt <input_file> <public_key_file> [output_file]")
            print("Example: python hybrid.py encrypt secret.txt public.pem encrypted.json")
            return
        #reads input file, public key file, and optional output file name
        input_file = sys.argv[2]
        pub_key_file = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else "encrypted.json"
        #calls file encryption function
        encrypt_file(input_file, pub_key_file, output_file)
    #encrypts text directly instead of a file
    elif command == "encrypt-text":
        if len(sys.argv) < 4:
            print("Usage: python hybrid.py encrypt-text '<text>' <public_key_file> [output_file]")
            print("Example: python hybrid.py encrypt-text 'Hello World' public.pem message.enc")
            return
        #reads plaintext message, public key, and output file
        text = sys.argv[2]
        pub_key_file = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else "encrypted.json"
        #calls text encryption function
        encrypt_text(text, pub_key_file, output_file)
    #decrypts an encrypted JSON file
    elif command == "decrypt":
        if len(sys.argv) < 4:
            print("Usage: python hybrid.py decrypt <encrypted_file> <private_key_file> [output_file]")
            print("Example: python hybrid.py decrypt encrypted.json private.pem decrypted.txt")
            return
        #reads encrypted package, private key, and output file name
        input_file = sys.argv[2]
        priv_key_file = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else "decrypted.bin"
        #calls decryption function
        decrypt_file(input_file, priv_key_file, output_file)
    #handles invalid commands
    else:
        print(f"Unknown command: {command}")
        print("Available commands: genkeys, encrypt, encrypt-text, decrypt, help")
#generates RSA public/private key pair
def generate_keys():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    print("Generating RSA key pair...")
    #creates secure 2048 bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    #derives public key from private key
    public_key = private_key.public_key()
    
    #save private key to disk in PEM format
    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    #save public key to disk in PEM format
    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("✓ Keys generated:")
    print("  - private.pem (RSA private key)")
    print("  - public.pem  (RSA public key)")

#encrypts file using AES, then encrypts AES key using RSA
def encrypt_file(input_file, pub_key_file, output_file):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    
    print(f"Encrypting {input_file}...")
    
    #load RSA public key
    with open(pub_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    #read input file
    with open(input_file, "rb") as f:
        data = f.read()
    
    #generate random 256 bit AES key
    aes_key = os.urandom(32)
    
    #creates random AES-GCM nonce
    nonce = os.urandom(12)
    #initialize AES-GCM encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    #encrypts file contents
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    #encrypt AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    #create encrypted package
    package = {
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
        'original_file': input_file,
        'original_size': len(data)
    }
    
    #save encrypted package
    with open(output_file, "w") as f:
        json.dump(package, f, indent=2) #writes encrypted package to disk
    
    print(f"✓ Encrypted to {output_file}")
    print(f"  Original size: {len(data)} bytes")
    print(f"  Encrypted size: {len(ciphertext)} bytes")

#same as file encryption, but operates on text input instead
def encrypt_text(text, pub_key_file, output_file):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    
    print("Encrypting text...")
    
    #load public key
    with open(pub_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    data = text.encode('utf-8')
    
    #generate random AES key
    aes_key = os.urandom(32)
    
    #encrypt data with AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    #encrypt AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    #create encrypted package
    package = {
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
        'is_text': True,
        'original_size': len(data)
    }
    
    #save encrypted package
    with open(output_file, "w") as f:
        json.dump(package, f, indent=2)
    
    print(f"✓ Encrypted to {output_file}")

def decrypt_file(input_file, priv_key_file, output_file):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    
    print(f"Decrypting {input_file}...")
    
    #load private key
    with open(priv_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    #load encrypted package
    with open(input_file, "r") as f:
        package = json.load(f)
    
    #decode base64 values
    encrypted_key = base64.b64decode(package['encrypted_key'])
    ciphertext = base64.b64decode(package['ciphertext'])
    nonce = base64.b64decode(package['nonce'])
    tag = base64.b64decode(package['tag'])
    
    #decrypt AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    #decrypt data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    
    #save decrypted data
    with open(output_file, "wb") as f:
        f.write(decrypted)
    
    #try to display as text if it was text
    if package.get('is_text', False):
        try:
            text = decrypted.decode('utf-8')
            print(f"✓ Decrypted text saved to {output_file}")
            print(f"Text content: {text[:100]}..." if len(text) > 100 else f"Text content: {text}")
        except:
            print(f"✓ Decrypted binary data saved to {output_file}")
    else:
        print(f"✓ Decrypted to {output_file}")
        print(f"  Decrypted size: {len(decrypted)} bytes")

if __name__ == "__main__":
    main()