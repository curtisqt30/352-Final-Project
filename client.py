import socket
import os
import threading
import pwinput
from tqdm import tqdm
import json
import sys

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
            print(f"Server response: {response}")
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
        command = "LIST_PEERS"
        response = self.send_command(command)
        if response:
            peers = response.split(",")
            if not peers:
                print("No active peers found.")
            else:
                print("Active peers:")
                for peer in peers:
                    ip, port = peer.split(":")
                    print(f"IP: {ip}, Port: {port}")

    def list_files(self):
        command = "LIST_FILES" 
        response = self.send_command(command)
        if response:
            try:
                file_list = eval(response)
                print("Available files:")
                for file_entry in file_list:
                    print(f"File: {file_entry['filename']}")
                    for peer in file_entry['peers']:
                        print(f"  - Offered by: {peer[0]}:{peer[1]}")
            except Exception as e:
                print(f"Error processing file list: {e}")

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
    
    # Generate RSA keys for client
    private_key, public_key = generate_RSA_keypair()
    print("\nClient RSA Private Key:")
    print(private_key.decode())
    sys.stdout.flush()
    print("\nClient RSA Public Key:")
    print(public_key.decode())
    sys.stdout.flush()
    print("")
    
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
                print("Login successful!")
                # Once logged in, show possible operations
                while True:
                    print("\nChoose an action:")
                    print("[1] Upload file")
                    print("[2] List active peers")
                    print("[3] List available files")
                    print("[4] Download file")
                    print("[5] Exit")
                    action = input("\nEnter the number of your choice: ").strip()
                    
                    if action == "1":  # Upload file
                        filename = input("Enter file path to upload: ")
                        client.handle_index(filename, 5001, username)
                    elif action == "2":  # List peers
                        client.list_peers()
                    elif action == "3":  # List files
                        client.list_files()
                    elif action == "4":  # Download file
                        peer_ip = input("Enter peer IP: ")
                        peer_port = int(input("Enter peer port: "))
                        filename = input("Enter filename to download: ")
                        client.request_file_from_peer(peer_ip, peer_port, filename)
                    elif action == "5":  # Exit
                        print("Exiting...")
                        break
                    else:
                        print("Invalid action. Try again.")
                break  # Exit loop after successful login
            else:
                print("\nLogin failed. Please check your credentials.")
        
        elif action == "2":  # Register
            username = input("\nEnter your new username: ")
            password = pwinput.pwinput(prompt="Enter your new password: ")
            if client.register(username, password):
                print("Registration successful! Now login.")
                continue
            else:
                print("Registration failed. Please try again.")
        
        elif action == "3":  # Exit
            print("Exiting program...")
            break
        
        else:
            print("Invalid option. Please enter a valid number (1, 2, or 3).")
    
    client.disconnect()
