import socket
import os
import threading
import pwinput
from tqdm import tqdm
import json
import sys

from util import (
    aes_encrypt_file,
    aes_decrypt_file,
    generate_AES_key,
    hash_file,
    store_password,
    load_stored_password,
    verify_password,
    load_json,
    save_json,
    load_database,
    save_database,
    generate_RSA_keypair,
    rsa_encrypt,
    rsa_decrypt,
    sign_data_rsa,
    verify_signature_rsa,
    generate_DSA_keypair,
    sign_data_dsa,
    verify_signature_dsa,
    save_key,
    load_key,
    get_current_timestamp,

)


class Client:
    def __init__(self, server_ip="0.0.0.0", port_number=55555):
        self.server_ip = server_ip
        self.port_number = port_number
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
        try:
            self.cli_sock.connect((self.server_ip, self.port_number))
            print(f"Connected to server {self.server_ip} on port {self.port_number}")
        except Exception as e:
            print(f"Failed to connect: {e}")
            self.disconnect()  # Disconnect if connection fails
            exit(1)  # Exit the program

    def login(self, username, password):
        command = f"LOGIN {username} {password}"
        response = self.send_command(command)
        return response == "LOGIN_SUCCESS"

    def register(self, username, password):
        command = f"REGISTER {username} {password}"
        response = self.send_command(command)
        return response == "REGISTER_SUCCESS"

    def disconnect(self):
        self.cli_sock.close()
        print("Disconnected from server.")

    def send_command(self, command):
        try:
            self.cli_sock.send(command.encode())
            response = self.cli_sock.recv(1024).decode()
            print(f"\nServer response:\n{response}")
            return response
        except Exception as e:
            print(f"Error sending command: {e}")
            return f"Error: {e}"

    def handle_index(self, filename, port, username):
        # Check if the file exists
        if not os.path.exists(filename):
            print(f"File {filename} doesn't exist.")
            return

        # Send the command to index the file with the username and port
        command = f"INDEX {filename} {username} {port}"
        response = self.send_command(command)

        # Print the response from the server
        if response:
            print(f"Indexing response: {response}")

    def list_peers(self):
        self.send_command("LIST_PEERS")
        
    def list_files(self):
        self.send_command("LIST_FILES")

    def request_file_from_peer(self, peer_ip, peer_port, filename):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
                peer_sock.connect((peer_ip, peer_port))
                peer_sock.send(f"REQUEST {filename}".encode())
                
                # Get the file size first to display a progress bar
                peer_sock.send("GET_SIZE".encode())
                file_size = int(peer_sock.recv(1024).decode())  # Receive the size of the file

                with open(f"downloaded_{filename}", "wb") as f:
                    print(f"Downloading {filename} from {peer_ip}:{peer_port}...")
                    
                    # Initialize the tqdm progress bar
                    with tqdm(total=file_size, unit="B", unit_scale=True) as pbar:
                        total_received = 0
                        while True:
                            data = peer_sock.recv(1024)
                            if not data:
                                break
                            f.write(data)
                            total_received += len(data)
                            pbar.update(len(data))  # Update progress bar 

                    print(f"\nFile {filename} downloaded successfully.")
        except Exception as e:
            print(f"Failed to request file from peer: {e}")

if __name__ == "__main__":
    
    '''
    # Generate RSA keys for client
    private_key, public_key = generate_RSA_keypair()
    print("\nClient RSA Private Key:")
    print(private_key.decode())
    sys.stdout.flush()
    print("\nClient RSA Public Key:")
    print(public_key.decode())
    sys.stdout.flush()
    print("")
    '''
    
    server_ip = "127.0.0.1"
    port_number = 55555
    
    client = Client(server_ip=server_ip, port_number=port_number)
    client.connect()  # If connection fails, exit

    while True:
        # Display numbered options
        print("\nSelect an option:")
        print("[1] Login")
        print("[2] Register")
        print("[3] Exit")
        
        # Get user input for action selection
        action = input("\nEnter the number of your choice: ").strip()
        
        if action == "1":  # Login
            username = input("\nEnter your username: ")
            password = pwinput.pwinput(prompt="Enter your password: ") 
            if client.login(username, password):
                # Once logged in, show possible operations
                while True:
                    print("\nSelect an option:")
                    print("[1] Index Files")
                    print("[2] Connect")
                    print("[3] List Indices")
                    print("[4] Exit")
                    
                    action = input("\nEnter your choice: ").strip()
                    
                    if action == "1":  # Index Files
                        filename = input("Enter file path to upload: ")
                        client.handle_index(filename, 5001, username)

                    elif action == "2":  # Connect Submenu
                        while True:
                            print("\nConnect Options:")
                            print("[1] List Active Peers")
                            print("[2] Manage Incoming Requests")
                            print("[3] Send Connection Request")
                            print("[4] Back to Main Menu")
                            connect_action = input("\nEnter your choice: ").strip()
                            if connect_action == "1":
                                client.list_peers()
                            elif connect_action == "2":
                                print("Handling incoming requests... (not implemented)")
                            elif connect_action == "3":
                                peer_ip = input("Enter the peer's IP: ")
                                peer_port = input("Enter the peer's port: ")
                                client.send_command(f"REQUEST_PEER {peer_ip} {peer_port}")
                            elif connect_action == "4":
                                break
                            else:
                                print("Invalid option. Please try again.")
                    
                    elif action == "3":  # List files
                        client.list_files()
                    elif action == "4":  # Exit
                        print("Exiting program...")
                        break
                    
                    else:
                        print("Invalid option. Please enter a valid number (1-4).")
                break  # Exit loop after successful login
            else:
                print("\nPlease check your credentials.")
        
        elif action == "2":  # Register
            username = input("\nEnter your new username: ")
            password = pwinput.pwinput(prompt="Enter your new password: ")
            if client.register(username, password):
                continue
            else:
                print("Please try again.")
        
        elif action == "3":  # Exit
            print("Exiting program...")
            break
        
        else:
            print("Invalid option. Please enter a valid number (1, 2, or 3).")
    
    client.disconnect()
