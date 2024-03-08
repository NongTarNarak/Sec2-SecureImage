from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

def generate_key(password):
    """
    Generate a 256-bit AES key from a password.
    """
    return sha256(password.encode()).digest()

def encrypt_image(image_path, password):
    """
    Encrypt an image file using AES algorithm.
    """
    key = generate_key(password)
    cipher = AES.new(key, AES.MODE_CBC)

    with open(image_path, 'rb') as f:
        plaintext = f.read()
    
    # Padding plaintext to match block size
    padded_plaintext = pad(plaintext, AES.block_size)

    ciphertext = cipher.iv + cipher.encrypt(padded_plaintext)

    return key, ciphertext

def decrypt_image(ciphertext, key):
    """
    Decrypt an image file using AES algorithm.
    """
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext

# Example usage
image_path = 'example_image.jpg'
password = 'mysecretpassword'

key, ciphertext = encrypt_image(image_path, password)
print("Key:", key)
print("Ciphertext:", ciphertext)

# Decrypting the image
decrypted_data = decrypt_image(ciphertext, key)

# Writing decrypted data to a new image file
with open('decrypted_image.jpg', 'wb') as f:
    f.write(decrypted_data)

print("Image decrypted successfully.")
