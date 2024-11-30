import tkinter as tk
from tkinter import messagebox, filedialog
from client import Client
from encryption_util import (
    aes_encrypt_file,
    aes_decrypt_file,
    generate_AES_key,
    hash_file,
    store_password,
    load_stored_password,
    verify_password,
    generate_RSA_keypair,
    rsa_encrypt,
    rsa_decrypt,
    sign_data_rsa,
    verify_signature_rsa,
    generate_DSA_keypair,
    sign_data_dsa,
    verify_signature_dsa,
    save_key,
    load_key
)

client = Client(server_ip="127.0.0.1", port_number=5000)

# Initialize main Tkinter window
m = tk.Tk()
m.title("Secure File Sharing System")

# Center the window
screen_width = m.winfo_screenwidth()
screen_height = m.winfo_screenheight()
window_width = 600
window_height = 400
position_top = int(screen_height / 2 - window_height / 2)
position_right = int(screen_width / 2 - window_width / 2)

# Set the position and size
m.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

def connect_to_server():
    try:
        client.connect()  # call connect function from client class
        messagebox.showinfo("Connection Status", "Connected to server!")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")

def login():
    username = username_entry.get()
    password = password_entry.get()
    
    if verify_password(username, password):
        messagebox.showinfo("Login", "Login successful!")
        
        # Close the login window
        m.destroy()  
        
        main_window = tk.Tk()
        main_window.title("Secure File Sharing")
        main_window.geometry("600x400")

        upload_button = tk.Button(main_window, text="Upload File", command=upload_file)
        upload_button.pack(pady=20)
        
        transfer_button = tk.Button(main_window, text="Start Transfer", command=start_transfer)
        transfer_button.pack(pady=5)
        
        search_button = tk.Button(main_window, text="Search Files", command=search_file)
        search_button.pack(pady=5)
        
        exit_button = tk.Button(main_window, text="Exit", command=exit_application)
        exit_button.pack(pady=5)

        # Start the main window loop
        main_window.mainloop()
        
    else:
        messagebox.showerror("Login", "Invalid credentials.")

        
def create_account():
    # Create a new window for account creation
    account_window = tk.Toplevel(m)  
    account_window.title("Create Account")
    
    # Center the "Create Account" window
    screen_width = m.winfo_screenwidth()
    screen_height = m.winfo_screenheight()
    account_window_width = 400
    account_window_height = 300
    position_top = int(screen_height / 2 - account_window_height / 2)
    position_right = int(screen_width / 2 - account_window_width / 2)
    
    # Set the position and size for account creation window
    account_window.geometry(f'{account_window_width}x{account_window_height}+{position_right}+{position_top}')

    def submit_account():
        username = new_username_entry.get()
        password = new_password_entry.get()
        if username and password:
            try:
                store_password(username, password) 
                messagebox.showinfo("Account Creation", "Account created successfully!")
                account_window.destroy() 
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create account: {e}")
                account_window.destroy() 
        account_window.withdraw()  
        messagebox.showwarning("Input Error", "Please fill in both fields.")
        account_window.deiconify()  

    # Username Entry
    new_username_label = tk.Label(account_window, text="New Username:")
    new_username_label.pack(pady=5)
    new_username_entry = tk.Entry(account_window)
    new_username_entry.pack(pady=5)

    # Password Entry 
    new_password_label = tk.Label(account_window, text="New Password:")
    new_password_label.pack(pady=5)
    new_password_entry = tk.Entry(account_window, show="*")
    new_password_entry.pack(pady=5)

    # Add the submit button
    submit_button = tk.Button(account_window, text="Create Account", command=submit_account)
    submit_button.pack(pady=20)

def upload_file():
    # Open a file dialog to select a file to upload
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            client.handle_index(file_path, 5001)  # test port
            messagebox.showinfo("Upload File", f"File {file_path} indexed successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload file: {e}")

def search_file():
    filename = filedialog.askstring("Search File", "Enter the filename to search:")
    if filename:
        try:
            client.handle_search(filename)  # Search the file
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {e}")

def start_transfer():
    filename = filedialog.askopenfilename()
    if filename:
        peer_ip = "127.0.0.1"  # test peer IP for direct file sharing
        peer_port = 5002        # test peer port
        try:
            client.request_file_from_peer(peer_ip, peer_port, filename)
        except Exception as e:
            messagebox.showerror("Error", f"Transfer failed: {e}")

def exit_application():
    client.disconnect()
    m.quit()

# Username Entry
username_label = tk.Label(m, text="Username:")
username_label.pack(pady=5)
username_entry = tk.Entry(m)
username_entry.pack(pady=5)

# Password Entry 
password_label = tk.Label(m, text="Password:")
password_label.pack(pady=5)
password_entry = tk.Entry(m, show="*") 
password_entry.pack(pady=5)

# Login Button
login_button = tk.Button(m, text="Login", command=login)
login_button.pack(pady=20)

# Create Account Button
create_account_button = tk.Button(m, text="Create Account", command=create_account)
create_account_button.pack(pady=5)

# Exit Button
exit_button = tk.Button(m, text="Exit", command=exit_application)
exit_button.pack(pady=5)

# Run the Tkinter main loop
m.mainloop()
