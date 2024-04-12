import tkinter as tk
from tkinter import ttk

def gui(image_info):
    def show_main_menu():
        # Clearing the frame
        for widget in frame.winfo_children():
            widget.destroy()

        # Main menu buttons

        tk.Button(frame, text="List Down All Images", command=lambda: list_images(image_info)).pack(fill=tk.X)

    def list_images(image_dict):
        # Clearing the frame
        for widget in frame.winfo_children():
            widget.destroy()

        # Go Back Button at the top left
        back_button = tk.Button(frame, text="<--", command=show_main_menu)
        back_button.pack(side=tk.TOP, anchor='nw')

        # Creating the treeview
        columns = ("Image Name", "Image File Type")
        tree = ttk.Treeview(frame, columns=columns, show='headings')
        tree.heading('Image Name', text='Image Name', anchor='center')
        tree.heading('Image File Type', text='Image File Type', anchor='center')

        # Changing the column settings so that text is centered
        tree.column('Image Name', anchor='center', stretch=True)
        tree.column('Image File Type', anchor='center', stretch=True)

        # Adding data to the treeview
        for image_name, details in image_dict.items():
            tree.insert("", tk.END, values=(image_name, details[2]))  # Index 2 for the file type

        tree.pack(expand=True, fill='both')

    # Define other functions (toggle_password, save_image, get_image, save_image_data, fetch_image_data) here.

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
    "deskmatelogo": ["String1", "String2", ".png"],
    "test": ["String1", "String2", ".png"],
    "CVTatarLupsudyod": ["String1", "String2", ".jpg"],
}

# Call the function to display the GUI
gui(image_dict)
