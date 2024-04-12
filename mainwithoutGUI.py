# Pakkaphan Permvanitkul 6587094
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import os
import time # use for delaying the program
import json # use for import and export json file format
# Cipher text and Key from AES is bytes type and when we export that we must change into string type
# because json cannot contain bytes format type
# and the problem occurs when we want to change the string into the original bytes format
# so we use module called "ast" to change string into bytes type.
import ast #use for parse the string to bytes


# AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE
# AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE
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
# AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE
# AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE AES ZONE




# RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE
# RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE
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
# RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE
# RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE RC4 ZONE


def verify_encrpyt_input(image_path,image_file_type):
    whitelistFileType = ['.jpeg','.jpg','.png','.bmp'];
    path = True;
    filetype = True;

    # CHECK PATH
    try:
        with open(image_path, 'rb') as f:
            plaintext = f.read()
    except:
        path = False;
        print();
        print(">> ** Path not Avaliable **");
        print();
        time.sleep(1);
    
    if(image_file_type not in whitelistFileType):
        print();
        print(">> ** File type Not Avaliable **");
        print();
        time.sleep(1);
        filetype = False;
    return (path and filetype);
    

def list_image_details(allEncryptImageDict):
    uploadcheck = (details[4] for details in allEncryptImageDict.values())

    # Print header
    print(f"+{'-' * (69)}+")
    print(f"| {' ' * 5}{'Image Name':^{23}}{' ' * 5} | {' ' * 5}{'Image File Type':^{21}}{' ' * 5} |")
    print(f"+{'-' * (69)}+")

    # Print rows
    for name, details in allEncryptImageDict.items():
        encrypted_aesKey, ciphertext, image_file_type,  = details
        
        # if length of name is longer than table
        if(len(name) > 33):
            name = name[:-5]+ "...";
            
       
        if(uploadcheck == "Y"):
            print(f"| {name:^{33}} | {image_file_type:^{31}} |");
        else:
            print(f"| {name:^{33}} | {image_file_type:^{31}} |");
            
    # Print bottom border
    print(f"+{'-' * (69)}+");
    

def convert_string_to_bytes(byte_str):
    # Using ast.literal_eval() to evaluate the string as a Python expression
    byte_data = ast.literal_eval(byte_str)

    return byte_data


# MAIN ZONE
if __name__ == "__main__":
    allEncryptImageDict = {}
    
# LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM
# LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM
    folder_path = './CipherText/'
    # Loop through files in the folder
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        
        # Check if the current item in the folder is a file
        if os.path.isfile(file_path):
            # Here you can treat each file as an object
            with open(file_path, "r") as json_file:
                data = json.load(json_file)
                # file_content is json with
                #  data = {
                #     "name": name,
                #     "cipher": str(ciphertext),
                #     "encrypted_aesKey": str(encrypted_aesKey),
                #     "filetype": image_file_type
                # }

                name,cipherdata,encrypted_aesKey,filetype = data["name"],data["cipher"],data["encrypted_aesKey"],data["filetype"]
                cipherdata = convert_string_to_bytes(cipherdata) #make string that we've read to be the byte type
        
                encrypted_aesKey = bytearray(convert_string_to_bytes(encrypted_aesKey[10:-1])) #make string to arraybyte type
                tempObject = [encrypted_aesKey,cipherdata,filetype]
             
                # set image_name as key, set tempObject as values contain all of importance data
                allEncryptImageDict[name] = tempObject
# LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM
# LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM LOAD ALL ENCRYPTED FILE TO SYSTEM

    print();
    print(" ******** HOW TO USE IN README.md ******** ")
    print();

    
    while True:
        print('---------- Secure Image System ----------');
        print('Type 1: Save the image with AES');
        print('Type 2: Get the image');
        print('Type 3: List all encrpyted image name');
        print('Type r: reboot');
        print('Type x: exit');
        
        
        x = str(input('>>')).lower();
        whitelistchoice = ['1','2','3','x','X','r','R']
        if x not in whitelistchoice:
            print()
            time.sleep(0.4)
            print('>> * Invalid syntax. Please provide the correct input format *')
            time.sleep(0.8)
            print()
            continue
            
        
        if(x == '1'):
            image_path = str(input('Put your image path here >> ./PlainText_image/'))
            image_name = str(input('Image name >>'))
            password = str(input('Password For Master Key (Generate by SHA256) [Must remember] >>'))
            print()
     
            
            # get the file type from image name
            temptype = image_path.split('.')
            image_file_type = '.'+temptype[-1]
      

            
            # this step we verify some of input
            image_path = "./PlainText_image/"+image_path
            if(verify_encrpyt_input(image_path,image_file_type)):
    
                key, ciphertext = encrypt_image(image_path, password); 
                
                passwordbyte = password.encode('utf-8') #make password from user to byte type before use it to encrypt aes key
                encrypted_aesKey = rc4_encrypt(passwordbyte, key) #we will get arraybyte type
                # now we encrypt AES key with user password using RC4
                
                tempObject = [encrypted_aesKey,ciphertext,image_file_type];
                # When it's time to decrypt just decrypt "encrypted_aesKey" using RC4 first
                # and decypt image cipher image with that decrypted key
                
                # set image_name as key, set tempObject as values contain all of importance data
                allEncryptImageDict[image_name] = tempObject;
                
            else:
                print();
                print('>> ** Failed to encrypt reboot ... **');
                time.sleep(2);
                print();
                continue;
        
                
                
        elif(x == '2'):
            image_name = str(input("Image's name for decryption >>"));
            password_decrypt = str(input("password >>"));
            
            
            # verifying input
            try:
                objectyouwanttoDecrypt = allEncryptImageDict[image_name]
                    
                # always change it into bytes by using .encode("utf-8")
                encrypted_aesKey, ciphertext = objectyouwanttoDecrypt[0],objectyouwanttoDecrypt[1];
                
                bytearraytypeKeyThatEncryptedwithRC4 = encrypted_aesKey
                passfordecrpytbyte = password_decrypt.encode() #password must encode() to byte type from string
            
                # decrypt aes key now we got original AES Key to decrypt cipher image
                AESKEYarraybyte = rc4_decrypt(passfordecrpytbyte, bytearraytypeKeyThatEncryptedwithRC4) 
                AESKEYbyte= bytes(AESKEYarraybyte)
                
                # Decrypting data
                decrypted_data = decrypt_image(ciphertext, AESKEYbyte);
                    

                # Writing decrypted data to a new image file
                outputfilename =  image_name+allEncryptImageDict[image_name][2];
                
                with open("./Decrypted_image/"+outputfilename, 'wb') as f:
                    f.write(decrypted_data);
                    
                print();
                print(f">> ** {image_name} decrypted successfully. **")
                print();
                time.sleep(1);
            except:
                print();
                print(f">> ** There are not images named '{image_name}' or incorrect password **");
                print();
                time.sleep(1);
            
        elif(x == '3'):
            print();
            time.sleep(0.4);
            list_image_details(allEncryptImageDict);
            time.sleep(0.4);
            print();
            continue;
        
   
        elif(x == 'x'):
            
            for name,value in allEncryptImageDict.items():
                object_to_write_out = value; 
                encrypted_aesKey = object_to_write_out[0]; 
                ciphertext = object_to_write_out[1]; 
                image_file_type = object_to_write_out[2]; 
                    
                data = {
                    "name": name,
                    "cipher": str(ciphertext),
                    "encrypted_aesKey": str(encrypted_aesKey),
                    "filetype": image_file_type
                }

                # File path to write JSON data
                file_path = "CipherText/"+name+".json"

                # Writing data to JSON file
                with open(file_path, "w") as json_file:
                    json.dump(data, json_file)
                    
                print()
                print(f'>> Saving image: {data["name"]}')
                print()
                time.sleep(0.3)

            print();
            print(">> * Save out all object to .json *");
            print();
                
            time.sleep(1);
            print('Exiting . . .');
            time.sleep(0);
            print('Bye Bye C;');
            break
        elif(x == 'r'):
            print()
            time.sleep(1)
            print('>> **  rebooting . . .  **')
            time.sleep(1)
            print()
            continue;
            

      
        
        
        
        