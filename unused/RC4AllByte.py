import ast
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

# AES ZONEEEEEEE
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


# RC4 ZONEEEE
def ksa(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S, plaintext):
    i = j = 0
    out = bytearray()
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return out

def rc4_encrypt(key, plaintext):
    key = bytearray(key)  # Convert key to byte array
    S = ksa(key)
    plaintext = bytearray(plaintext)  # Convert plaintext to byte array
    return prga(S, plaintext)

def rc4_decrypt(key, ciphertext):
    return rc4_encrypt(key, ciphertext)  # RC4 decryption is the same as encryption

def convert_string_to_bytes(byte_str):
    # Using ast.literal_eval() to evaluate the string as a Python expression
    byte_data = ast.literal_eval(byte_str)

    return byte_data

# Example usage:
key = b'SecretKey'  # Key should be bytes
plaintext = b"Hello, World!"  # Plain text should be bytes
encrypted_text = rc4_encrypt(key, plaintext)
print("Encrypted:", encrypted_text)
decrypted_text = rc4_decrypt(key, encrypted_text)
print("Decrypted:", decrypted_text.decode())





if __name__ == "__main__":
    # 1 input for encrypt image with aes
    image_name = input('name >>')
    password = input('passwd >>') #this is key
    imagepath = 'phanphum.png' #the plaintext
    imgpath = "./PlainText_image/" + imagepath
    
    # 2 encrypt image with password
    key, ciphertext = encrypt_image(imgpath, password)
    # after this we will get the AES key and cipher text we want to encrypt AES key with RC4
    print(key)
    
    # 3 encrypt aes key with user password
    passwordbyte = password.encode('utf-8') #make password from user to byte type before use it to encrypt aes key
    encrypted_aesKey = rc4_encrypt(passwordbyte, key) #we will get arraybyte type

    # 4 save out with json file format
    data = {
                    "name": image_name,
                    "cipher": str(ciphertext),
                    "encrypted_aesKey": str(encrypted_aesKey),
                    "filetype": '.png'
                }

    with open('jsontesting.json', "w") as json_file:
            json.dump(data, json_file)
            
            
            
    # 1 decryption 
    with open('jsontesting.json', "r") as json_file:
        data = json.load(json_file)
    
    name,cipherdata,key = data["name"],data["cipher"],data["encrypted_aesKey"];
    
    # 2 first of all make key from string-bytearray type to bytearray type
    bytearraytypeKeyThatencryptedwithRC4 = bytearray(convert_string_to_bytes(key[10:-1]))

    # 3 get the password from user to decrypt AES key first with RC4
    passfordecrpytAesKey = input('passwd for decrypt >>') #ya luem encode
    passfordecrpytbyte = passfordecrpytAesKey.encode()
    
    # 4 decrypt aes key now we got original AES Key to decrypt cipher image
    AESKEYarraybyte = rc4_decrypt(passfordecrpytbyte, bytearraytypeKeyThatencryptedwithRC4) 
    AESKEYbyte= bytes(AESKEYarraybyte)
    
    # 5 change cipher text from string to byte with ast library
    cipherimageToBYTE = convert_string_to_bytes(cipherdata)
    
    # 6 decrypt cipher text with aes key
    decryptedIMAGE = decrypt_image(cipherimageToBYTE, AESKEYbyte);
    
    # 7 write out the image
    with open("./Decrypted_image/testcomplete.jpg", 'wb') as f:
        f.write(decryptedIMAGE);
    
    