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
m.geometry("600x400")

def connect_to_server():
    try:
        client.connect() # call connect function from client class
        messagebox.showinfo("Connection Status", "Connected to server!")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")

def login():
    username = username_entry.get()
    password = password_entry.get()
    if verify_password(username, password):
        messagebox.showinfo("Login", "Login successful!")
    else:
        messagebox.showerror("Login", "Invalid credentials.")
        
def create_account():
    # Create a new window for account creation
    account_window = tk.Toplevel(m)  
    account_window.title("Create Account")
    account_window.geometry("400x300")

    def submit_account():
        username = new_username_entry.get()
        password = new_password_entry.get()
        if username and password:
            try:
                store_password(username, password)  # Save the credentials securely
                messagebox.showinfo("Account Creation", "Account created successfully!")
                account_window.destroy()  # Close the account creation window
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create account: {e}")
        else:
            messagebox.showwarning("Input Error", "Please fill in both fields.")

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
    pass

def search_file():
    pass

def start_transfer():
    pass

def exit_application():
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