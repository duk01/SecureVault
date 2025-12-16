# SecureVault

----------------------------------------------------------------------------------------------------------------------------
*** WEEK 2 *** (aes.py, aes.csv)

  1. Run aes.py
  2. Output shows decryption
     
----------------------------------------------------------------------------------------------------------------------------
*** WEEK 3 *** (main.py)

  1. Run main.py
  2. Enter message
  3. Outputs ciphertext, then back to plaintext
     
----------------------------------------------------------------------------------------------------------------------------
*** WEEK 4 *** (hybrid.py, secret.txt)

1. Generate keys:
     python hybrid.py genkeys
2. Encrypt a file:
     python hybrid.py encrypt secret.txt public.pem
             OR
3. Encrypt text:
     python hybrid.py encrypt-text "Hello World" public.pem
4. Decrypt:
     python hybrid.py decrypt encrypted.json private.pem
5. Decrypt with custom output:
     python hybrid.py decrypt encrypted.json private.pem result.txt

ENCRYPTION PROCESS:
  1. Generate random AES-256 key
  2. Encrypt data with AES-GCM
  3. Encrypt AES key with RSA-OAEP
  4. Package everything together

----------------------------------------------------------------------------------------------------------------------------
*** WEEK 5-10 *** (secure_server.py, secure_client.py, /attacks folder)

TO RUN NORMALLY :

  NEED TWO TERMINALS
    Terminal 1: Server
    Terminal 2: Client

  Terminal 1:
    Run python secure_server.py

  Terminal 2:
    Run python secure_client.py 127.0.0.1 5000

  Select option from menu and proceed
