from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import time;

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
                print("** Authentication Successful **");
                return True;
            else:
                print("** Password is not correct **");
                return False;
    except:
        print(f"** There are not images named '{name}' **");

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
        time.sleep(1);
        print();
        print(">> ** Path not Avaliable **");print();
    
    if(image_file_type not in whitelistFileType):
        time.sleep(1);
        print();
        print(">> ** File type Not Avaliable **");print();
        filetype = False;
    return (path and filetype);
    

def list_image_details(allEncryptImageDict):
    # Find the maximum lengths for each column
    max_name_length = max(len(name) for name in allEncryptImageDict.keys())
    max_password_length = max(len(details[2]) for details in allEncryptImageDict.values())
    max_file_type_length = max(len(details[3]) for details in allEncryptImageDict.values())


    # Print header
    print(f"+{'-' * (105)}+")
    print(f"| {' ' * 5}{'Image Name':^{23}}{' ' * 5} | {' ' * 5}{'Password Length':^{23}}{' ' * 5} | {' ' * 5}{'Image File Type':^{21}}{' ' * 5} |")
    print(f"+{'-' * (105)}+")

    # Print rows
    for name, details in allEncryptImageDict.items():
        key, ciphertext, password, image_file_type = details
        
        # if length of name is longer than table
        if(len(name) > 33):
            name = name[:-5]+ "...";
            
        masked_password = "*" * len(password)
        if(len(masked_password) > 27):
            # set constant of '*' if it overflow
            masked_password = '*' * 34;
            masked_password = masked_password[:-11] + "..." + " (" + str(len(password)) + ")";
            
        
        print(f"| {name:^{33}} | {masked_password:^{33}} | {image_file_type:^{31}} |")

    # Print bottom border
    print(f"+{'-' * (105)}+");
    
    
# MAIN ZONE
if __name__ == "__main__":
    allEncryptImageDict = {};
    print();
    print(" ******** HOW TO USE IN README.md ******** ");
    print();
    
    while True:
        print('---------- Image Secure System ----------');
        print('Type 1: Encrypt the image with AES.');
        print('Type 2: Decrypt the image.');
        print('Type 3: List all encrpyted image name.');
        print('Type 4: Show Cipher Text and Key.');
        print('Type x: EXIT');
        
        
        x = str(input('>>')).lower();
        whitelistchoice = ['1','2','3','x','X'];
        
        if(x == '1'):
            image_path = str(input('Put your image path here >>'));
            image_name = str(input('Image name >>'));
            image_file_type = str(input('Image type (.png .jpeg .jpg .bmp) >>'));
            password = str(input('Password For Master Key (Generate by SHA256) [Must remember] >>'));
            
            # this step we verify some of input
            if(verify_encrpyt_input(image_path,image_file_type)):
    
                key, ciphertext = encrypt_image(image_path, password); 
                tempObject = [key,ciphertext,password,image_file_type];
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
            password_decrypt = str(input("Password >>"));
            
            #Authenticate user with their image before decrypt
            if(verify_password(image_name,password_decrypt,allEncryptImageDict)):
                # Decrypting data
                decrypted_data = decrypt_image(ciphertext, key);

                # Writing decrypted data to a new image file
                outputfilename = image_name+allEncryptImageDict[image_name][3];
                
                with open(outputfilename, 'wb') as f:
                    f.write("./Decrypted_image"+decrypted_data);
                print("Image decrypted successfully.")
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
            continue;
        
        elif(x == 'x'):
            print('Exiting . . .');
            time.sleep(2);
            print('Bye Bye C;');
            break
            

      
        
        
        
        