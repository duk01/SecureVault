from cryptography.fernet import Fernet

#creating key
key = Fernet.generate_key()

with open('mykey.key', 'wb') as mykey:
    mykey.write(key)

#reusing key -- running this should match the key that was just generated
with open('mykey.key', 'rb') as mykey:
    key = mykey.read()
print(key)

#initialize fernet object, pass key to it, and store as local variable f
f = Fernet(key)

with open('aes.csv', 'rb') as original_file:
    original = original_file.read()

#encrypt data using Fernet object and store as encrypted

encrypted = f.encrypt(original)

#write into new encrypted csv file
with open('enc_aes.csv', 'wb') as encrypted_file:
    encrypted_file.write(encrypted)

#we should now have a new encrypted aes csv file
#now, we will decrypt the encrypted file 

f = Fernet(key)

#read the enc_aes.csv file and save it as 
with open('enc_aes.csv', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()

    decrypted = f.decrypt(encrypted)

#write into new csv file
with open('dec_aes.csv', 'wb') as decrypted_file:
    decrypted_file.write(decrypted)

#run this and it should decrypt the encrypted file