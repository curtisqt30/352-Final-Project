import tkinter as tk
from tkinter import messagebox, filedialog
from client import Client

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

# Password Entry (Masked Input)
password_label = tk.Label(m, text="Password:")
password_label.pack(pady=5)
password_entry = tk.Entry(m, show="*")  # Mask the input with '*'
password_entry.pack(pady=5)

# Login Button
login_button = tk.Button(m, text="Login", command=login)
login_button.pack(pady=20)

# Exit Button
exit_button = tk.Button(m, text="Exit", command=exit_application)
exit_button.pack(pady=5)

# Run the Tkinter main loop
m.mainloop()