# Pakkaphan Permvanitkul 6587094
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

import time # use for delaying the program
import json # use for import and export json file format
# Cipher text and Key from AES is bytes type and when we export that we must change into string type
# because json cannot contain bytes format type
# and the problem occurs when we want to change the string into the original bytes format
# so we use module called "ast" to change string into bytes type.
import ast #use for parse the string to bytes

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

def verify_password(name,passwd,allitems):
    try:
        package = allitems[name];
        if(package is not None):
            if(package[2] == passwd):
                print();
                print("** Authentication Successful **");
                print();
                time.sleep(1);
                return True;
            else:
                print();
                print("** Password is not correct **");
                print();
                time.sleep(1);
                return False;
    except:
        print();
        print(f"** There are not images named '{name}' **");
        print();
        time.sleep(1);
        return False;

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
    print(f"If you uploaded the image, the default password is set to 'ICT555'")
    print(f"+{'-' * (115)}+")
    print(f"| {' ' * 5}{'Image Name':^{23}}{' ' * 5} | {' ' * 5}{'Password Length':^{23}}{' ' * 5} | {' ' * 5}{'Image File Type':^{21}}{' ' * 5} | {'Upload':^{7}} |")
    print(f"+{'-' * (115)}+")

    # Print rows
    for name, details in allEncryptImageDict.items():
        key, ciphertext, password, image_file_type, uploadcheck = details
        
        # if length of name is longer than table
        if(len(name) > 33):
            name = name[:-5]+ "...";
            
        masked_password = "*" * len(password)
        if(len(masked_password) > 27):
            # set constant of '*' if it overflow
            masked_password = '*' * 34;
            masked_password = masked_password[:-11] + "..." + " (" + str(len(password)) + ")";
        
        if(uploadcheck == "Y"):
            print(f"| {name:^{33}} | {masked_password:^{33}} | {image_file_type:^{31}} | {uploadcheck:^{7}} |");
        else:
            print(f"| {name:^{33}} | {masked_password:^{33}} | {image_file_type:^{31}} | {uploadcheck:^{7}} |");
            
    # Print bottom border
    print(f"+{'-' * (115)}+");
    

def convert_string_to_bytes(byte_str):
    # Using ast.literal_eval() to evaluate the string as a Python expression
    byte_data = ast.literal_eval(byte_str)

    return byte_data


# MAIN ZONE
if __name__ == "__main__":
    allEncryptImageDict = {};
    print();
    print(" ******** HOW TO USE IN README.md ******** ");
    print();
    
    while True:
        print('---------- Secure Image System ----------');
        print('Type 1: Save the image with AES.');
        print('Type 2: Get the image.');
        print('Type 3: List all encrpyted image name.');
        print('Type 4: Export Cipher image and Key.');
        print('Type 5: Insert Cipher image to the system.')
        print('Type x: EXIT');
        
        
        x = str(input('>>')).lower();
        whitelistchoice = ['1','2','3','x','X'];
        
        if(x == '1'):
            image_path = str(input('Put your image path here >> ./PlainText_image/'));
            image_name = str(input('Image name >>'));
            image_file_type = str(input('Image type (.png .jpeg .jpg .bmp) >>'));
            password = str(input('Password For Master Key (Generate by SHA256) [Must remember] >>'));
            print();
            upload = "";
            
            # this step we verify some of input
            image_path = "./PlainText_image/"+image_path
            if(verify_encrpyt_input(image_path,image_file_type)):
    
                key, ciphertext = encrypt_image(image_path, password); 
                tempObject = [key,ciphertext,password,image_file_type,upload];
                # When it's time to decrypt just use Key as index 0, Ciphertext as index 1
                
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
            
            #Authenticate user with their image before decrypt
            if(verify_password(image_name,password_decrypt,allEncryptImageDict)):
                objectyouwanttoDecrypt = allEncryptImageDict[image_name]
                
                # always change it into bytes by using .encode("utf-8")
                key, ciphertext = objectyouwanttoDecrypt[0],objectyouwanttoDecrypt[1];
                
                
                if(type(key) != bytes or type(ciphertext) != bytes):
                    # In json cipher text and key are in the wrong format
                    # so we import ast module to change string to the original bytes
                    key, ciphertext = convert_string_to_bytes(key),convert_string_to_bytes(ciphertext)
                
                # print(key);
                # Decrypting data
                decrypted_data = decrypt_image(ciphertext, key);

                # Writing decrypted data to a new image file
                outputfilename =  image_name+allEncryptImageDict[image_name][3];
                
                with open("./Decrypted_image/"+outputfilename, 'wb') as f:
                    f.write(decrypted_data);
                
                print();
                print(f"** {image_name} decrypted successfully. **")
                print();
                time.sleep(1);
                
            else:
                # If authenticate failed
                continue;
            
        elif(x == '3'):
            print();
            time.sleep(1);
            list_image_details(allEncryptImageDict);
            time.sleep(1);
            print();
            continue;
        
        elif(x == '4'):
            print();
            print(f">> In this step we'll write out the encrypted file to .json file in folder (CipherText) as well the key.")
            print(f">> then if you want to decrypt that image you must type 5")
            
            image_name = str(input("Image's name to write out >>"));
            password_writefileout = str(input("password >>"));
            
            
            if(verify_password(image_name,password_writefileout,allEncryptImageDict)):
                object_to_write_out = allEncryptImageDict[image_name];
                
                key, ciphertext, password, image_file_type, upload = object_to_write_out;
                
                
                data = {
                    "name": image_name,
                    "cipher": str(ciphertext),
                    "filetype": image_file_type,
                    "key": str(key)
                }

                # File path to write JSON data
                file_path = "CipherText/"+image_name+".json"

                # Writing data to JSON file
                with open(file_path, "w") as json_file:
                    json.dump(data, json_file)

                print();
                print("Data has been written to", file_path);
                print();
                time.sleep(1);
                
                
            else:
                # If authenticate failed
                continue;
            
        elif(x == '5'):
            print("Option 1: Insert to system only");
            print("Option 2: Insert to system && decrypt to Decrypted_image folder");
            option = str(input(">>"));
            
            # File path of the JSON file to read
            file_path = str(input('JSON file path remember to put .json >> ./CipherText/'));

            file_path = "CipherText/"+file_path
            # Reading data from JSON file
            with open(file_path, "r") as json_file:
                data = json.load(json_file)
            
            
            name,cipherdata,filetype,key = data["name"],data["cipher"],data["filetype"],data["key"];
            
            
            # add upload signature set default password for upload to ICT555
            tempObject = [key,cipherdata,"ICT555",filetype,"Y"];
            # When it's time to decrypt just use Key as index 0, Ciphertext as index 1
            
            
            # set image_name as key, set tempObject as values contain all of importance data
            allEncryptImageDict[name] = tempObject;
            
            if(option == "2"):
                time.sleep(1);
                print();
                print('decrypting ...');
                print();
                time.sleep(1);
                
                key, ciphertext = convert_string_to_bytes(key),convert_string_to_bytes(cipherdata)
     
                # Decrypting data
                decrypted_data = decrypt_image(ciphertext, key);

                # Writing decrypted data to a new image file
                outputfilename =  name+filetype;
                
                with open("./Decrypted_image/"+outputfilename, 'wb') as f:
                    f.write(decrypted_data);
                
                print();
                print(f"** add & decrypted {name} successfully **")
                print();
                time.sleep(1);
                
            
            continue;
        
        elif(x == 'x'):
            print('Exiting . . .');
            time.sleep(2);
            print('Bye Bye C;');
            break
            

      
        
        
        
        