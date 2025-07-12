from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Constants
password = "your-secure-password"  # Replace with your real password
salt = get_random_bytes(16)
key = PBKDF2(password, salt, dkLen=32, count=100_000)

# Read data to encrypt
with open("seed.txt", "rb") as f:
    data = f.read()

# Encrypt
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)

# Save salt, nonce, tag, and ciphertext to file
with open("encrypted.bin", "wb") as f:
    f.write(salt)
    f.write(cipher.nonce)
    f.write(tag)
    f.write(ciphertext)

print("✅ Encryption successful. Output saved to encrypted.bin")
