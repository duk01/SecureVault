import rsa

#generate new RSA key pair
def generate_keys():
    (pubKey, privKey) = rsa.newkeys(1024) #1024 bit RSA key pair
    #saves public key to a file in PEM format
    with open('keys/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))
    #saves private key to disk
    with open('keys/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))
#load existing RSA keys from disk
def load_keys():
    #opens public key file
    with open('keys/pubkey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read()) #loads public key from PEM format
    #opens private key files
    with open('keys/privkey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read()) #loads private key
    #returns both keys to caller
    return pubKey, privKey
#encrypts message using public key
def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key) #converts message to bytes and encrypts using RSA
#decrypts ciphertext using private key
def decrypt(ciphertext, key):
    #attempts to decrypt ciphertext
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    #false if decryption fails
    except:
        return False
#signs a message using private key
def sign_sha1(msg, key):
    #hashes message with SHA-1 and signs hash with RSA
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')
#verifies digital signature using public key
def verify_sha1(msg, signature, key):
    try:
        #checks is signature matches message and signature used SHA-1
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    #verification fail
    except:
        return False
#generates new key pair every run, overwrites existing keys    
generate_keys()
#loads keys from disk
pubKey, privKey = load_keys()

message = input('Enter a message: ')
#encrypts using public key
ciphertext = encrypt(message, pubKey)
#creates digital signature using private key
signature = sign_sha1(message, privKey)
#decrypts ciphertext back to plaintext
plaintext = decrypt(ciphertext, privKey)

print(f'Cipher text: {ciphertext}')
print(f"Signature: {signature}")

if plaintext:
    print(f"Plain text: {plaintext}")
else:
    print("Could not decrypt the message.")
#verifies signature using public key
if verify_sha1(plaintext, signature, pubKey):
    print('Signature verified!')
else:
    print('Could not verify the message signature.')