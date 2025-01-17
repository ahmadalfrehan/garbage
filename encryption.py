from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
import os

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Symmetric encryption
def encrypt_data(data, public_key):
    symmetric_key = os.urandom(32)  # AES key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(os.urandom(16)))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Encrypt symmetric key using RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_key, ciphertext

# Decrypt function for hybrid encryption
def decrypt_data(encrypted_key, ciphertext, private_key):
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(os.urandom(16)))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
