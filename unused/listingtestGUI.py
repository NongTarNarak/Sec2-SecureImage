import tkinter as tk
from tkinter import ttk

def gui():
    def show_main_menu():
        # Clearing the frame
        for widget in frame.winfo_children():
            widget.destroy()

        # Readme Text
        readme_text = (
            "Secure Image System\n\n"
            "Welcome to the Secure Image System, powered by AES encryption and SHA-256 hashing.\n\n"
            "> Folder\n"
            "    CipherText:\n"
            "        - To export the encrypted images from the system in JSON format.\n"
            "        - System will decrypt all images from this folder.\n\n"
            "    Decrypted_image:\n"
            "        - All decrypted images will be stored in this designated folder.\n\n"
            "    PlainText_image:\n"
            "        - Place all images you wish to encrypt into this designated folder to start.\n"
            "        - If using the UI, you can select files from anywhere on your system.\n\n"
            "Powered by Pakkaphan Permvanitkul 6587094"
        )

        readme = tk.Text(frame, height=15, width=90)
        readme.pack()
        readme.insert(tk.END, readme_text)
        readme.config(state=tk.DISABLED)  # Make the text read-only

        # Main menu buttons
        # tk.Button(frame, text="Get the Image", command=get_image).pack(fill=tk.X)
        # tk.Button(frame, text="List Down All Images", command=list_images).pack(fill=tk.X)

    # ... other functions like get_image, list_images, toggle_password ...

    # Initialize the main window and main frame
    root = tk.Tk()
    root.title("Secure Image System by Group 2 Section 2")
    frame = tk.Frame(root)
    frame.pack(pady=20, expand=True, fill='both')

    # Start with the main menu
    show_main_menu()

    # Start the GUI event loop
    root.mainloop()

# Example dictionary to be passed
image_dict = {
    # ... your image dictionary ...
}

# Call the function to display the GUI
gui()
