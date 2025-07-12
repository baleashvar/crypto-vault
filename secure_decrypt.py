from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Constants
password = "your-secure-password"  # Use the *same* password used for encryption

# Read from file
with open("encrypted.bin", "rb") as f:
    salt = f.read(16)
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read()

# Derive key and decrypt
key = PBKDF2(password, salt, dkLen=32, count=100_000)
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    with open("decrypted_seed.txt", "wb") as f:
        f.write(plaintext)
    print("✅ Decryption successful. Output saved to decrypted_seed.txt")
except ValueError:
    print("❌ Decryption failed. Possible wrong password or corrupted file.")
