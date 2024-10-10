from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to encrypt the data
def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext

# Function to decrypt the data
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]  # Extract the IV from the first 16 bytes
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

# Example usage
key = os.urandom(32)  # Generate a 256-bit key
message = "This is a secret message!"

# Encrypt the message
encrypted_message = encrypt_message(key, message)
print(f"Encrypted message: {encrypted_message}")

# Decrypt the message
decrypted_message = decrypt_message(key, encrypted_message)
print(f"Decrypted message: {decrypted_message}")
