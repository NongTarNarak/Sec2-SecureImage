import os
import json
import ast
folder_path = './CipherText/'
allEncryptImageDict = {}

def convert_string_to_bytes(byte_str):
    # Using ast.literal_eval() to evaluate the string as a Python expression
    byte_data = ast.literal_eval(byte_str)
    return byte_data

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

     
            name,cipherdata,encrypted_aesKey,filetype = data["name"],data["cipher"],data["encrypted_aesKey"],data["filetype"];
            cipherdata = convert_string_to_bytes(cipherdata) #make string that we've read to be the byte type
       
            encrypted_aesKey = bytearray(convert_string_to_bytes(encrypted_aesKey[10:-1])) #make string to arraybyte type
            tempObject = [encrypted_aesKey,cipherdata,filetype];
            
            # set image_name as key, set tempObject as values contain all of importance data
            allEncryptImageDict[name] = tempObject;

# print(allEncryptImageDict)
            
          
            
     
