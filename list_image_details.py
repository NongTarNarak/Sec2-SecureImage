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
    

allEncryptImageDict = {
    "asdfasjdklfasdf": ["key1", "ciphertext1", "asdfasdfasdfsafd", "jpg"],
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": ["key2", "ciphertext2", "asdflaskjdfhlakjshdfkljasdhfl;aksjhdflaksdf", "png"],
    "image3": ["key3", "ciphertext3", "asdfkj;alsdjflaklsdkjfalskdjfalksdjfasdkljfasdf", "bmp"]
}

list_image_details(allEncryptImageDict)
