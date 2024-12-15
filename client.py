import socket
import os
import threading
import pwinput
from tqdm import tqdm
import json
import sys
import random

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
    def __init__(self, server_ip="0.0.0.0", port_number=49152):
        self.server_ip = server_ip
        self.port_number = port_number
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_port = random.randint(49153, 65535)
        self.incoming_requests = []
        self.local_file_directory = "client_files"
    
    # Connection Methods
    def connect(self):
        try:
            self.cli_sock.connect((self.server_ip, self.port_number))
            print(f"Connected to server {self.server_ip} on port {self.port_number}")
            self.cli_sock.send(f"LISTEN_PORT {self.listen_port}".encode())
            
            response = self.cli_sock.recv(1024).decode()
            if response == "LISTEN_PORT_ACK":
                print(f"Server acknowledged listen port: {self.listen_port}")
            else:
                print("Unexpected response from server:", response)
            
        except Exception as e:
            print(f"Failed to connect: {e}")
            self.disconnect()
            sys.exit(1)

    def disconnect(self):
        self.cli_sock.close()
        self.listen_sock.close()
        print("Disconnected from server.")
    
    # Listener Methods
    def start_listening(self):
        try:
            self.listen_sock.bind(("0.0.0.0", self.listen_port))
            self.listen_sock.listen(5)
            print(f"Listening for incoming requests on port {self.listen_port}...")
            threading.Thread(target=self.handle_incoming_connections, daemon=True).start()
        except Exception as e:
            print(f"Error starting listener: {e}")

    def handle_incoming_connections(self):
        while True:
            try:
                conn, addr = self.listen_sock.accept()
                print(f"Incoming connection from {addr}")
                threading.Thread(target=self.handle_peer_request, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def handle_peer_request(self, conn, addr):
        try:
            data = conn.recv(1024).decode()
            command, *args = data.split()
            
            if command == "REQUEST":
                self.send_file(conn, args[0])
            elif command == "GET_SIZE":
                self.send_file_size(conn, args[0])
            elif command == "CONNECTION_REQUEST":
                self.store_incoming_request(conn, addr)
            else:
                conn.send("ERROR: Unknown command".encode())
        except Exception as e:
            print(f"Error handling request from {addr}: {e}")
        finally:
            conn.close()

    def handle_connection_request(self, conn, addr):
        print(f"Incoming connection request from {addr}")
        # accept or reject connection 
        response = input("Accept connection? (yes/no): ").strip().lower()
        if response == "yes":
            conn.send("CONNECTION_ACCEPTED".encode())
            print(f"Connection with {addr} accepted.")
        else:
            conn.send("CONNECTION_REJECTED".encode())
            print(f"Connection with {addr} rejected.")

    # File Transfer
    def send_file(self, conn, filename):
        try:
            if not os.path.exists(filename):
                conn.send(f"ERROR: File not found: {filename}".encode())
                return
            with open(filename, "rb") as f:
                print(f"Sending file: {filename}")
                while chunk := f.read(1024):
                    conn.send(chunk)
            print(f"File {filename} sent successfully.")
        except Exception as e:
            print(f"Error sending file: {e}")

    def send_file_size(self, conn, filename):
        try:
            if not os.path.exists(filename):
                conn.send(f"ERROR: File not found: {filename}".encode())
                return
            file_size = os.path.getsize(filename)
            conn.send(str(file_size).encode())
        except Exception as e:
            print(f"Error sending file size: {e}")

    def request_file_from_peer(self, peer_ip, peer_port, filename):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
                peer_sock.connect((peer_ip, peer_port))
                peer_sock.send(f"REQUEST {filename}".encode())
                peer_sock.send("GET_SIZE".encode())
                file_size = int(peer_sock.recv(1024).decode())

                with open(f"downloaded_{filename}", "wb") as f, tqdm(total=file_size, unit="B", unit_scale=True) as pbar:
                    print(f"Downloading {filename} from {peer_ip}:{peer_port}...")
                    while data := peer_sock.recv(1024):
                        f.write(data)
                        pbar.update(len(data))
                print(f"File {filename} downloaded successfully.")
        except Exception as e:
            print(f"Failed to request file from peer: {e}")

    def store_incoming_request(self, conn, addr):
        self.incoming_requests.append((conn, addr))

    def manage_incoming_requests(self):
        if not self.incoming_requests:
            print("\nNo incoming connection requests.")
            return
        
        print("\nIncoming Connection Requests:")
        for index, (conn, addr) in enumerate(self.incoming_requests):
            print(f"[{index}] From {addr}")
        
        try:
            request_index = int(input("\nEnter the index of the request to manage or -1 to cancel: "))
            if request_index == -1:
                print("Returning to menu...")
                return
            
            conn, addr = self.incoming_requests[request_index]
            response = input(f"Accept connection from {addr}? (yes/no): ").strip().lower()
            if response == "yes":
                conn.send("CONNECTION_ACCEPTED".encode())
                print(f"Connection with {addr} accepted.")
            else:
                conn.send("CONNECTION_REJECTED".encode())
                print(f"Connection with {addr} rejected.")
            
            # Remove the handled request from the list
            del self.incoming_requests[request_index]
        except (ValueError, IndexError):
            print("Invalid option. Please try again.")

    # Commands
    def send_command(self, command):
        try:
            self.cli_sock.send(command.encode())
            response = self.cli_sock.recv(1024).decode()
            print(f"\nServer response:\n{response}")
            return response
        except Exception as e:
            print(f"Error sending command: {e}")
            return f"Error: {e}"

    def handle_index(self, filename, listen_port, username):
        if not os.path.exists(filename):
            print(f"File {filename} doesn't exist.")
            return
        response = self.send_command(f"INDEX {filename} {username} {listen_port}")
        print(f"Indexing response: {response}")
        
    def list_peers(self):
        self.send_command("LIST_PEERS")

    def list_files(self):
        self.send_command("LIST_FILES")

    # User Interface
    def main_menu(self):
        while True:
            print("\nSelect an option:")
            print("[1] Login")
            print("[2] Register")
            print("[3] Exit")
            choice = input("\nEnter your choice: ").strip()

            if choice == "1":
                self.handle_login()
            elif choice == "2":
                self.handle_registration()
            elif choice == "3":
                self.disconnect()
                break
            else:
                print("Invalid option. Please try again.")

    def login(self, username, password):
        command = f"LOGIN {username} {password}"
        response = self.send_command(command)
        return response == "LOGIN_SUCCESS"

    def register(self, username, password):
        command = f"REGISTER {username} {password}"
        response = self.send_command(command)
        return response == "REGISTER_SUCCESS"
 
    def handle_login(self):
        username = input("\nEnter your username: ")
        password = pwinput.pwinput(prompt="Enter your password: ")
        if self.login(username, password):
            self.logged_in_menu(username)
        else:
            print("Invalid credentials. Please try again.")

    def handle_registration(self):
        username = input("\nEnter your new username: ")
        password = pwinput.pwinput(prompt="Enter your new password: ")
        self.register(username, password)

    def logged_in_menu(self, username):
        while True:
            print("\nSelect an option:")
            print("[1] Connect")
            print("[2] Index a File")
            print("[3] List Indexed Files")
            print("[4] Exit")

            action = input("\nEnter your choice: ").strip()

            if action == "1":
                self.connect_menu()
            elif action == "2":
                filename = input("Enter file path to upload: ")
                self.handle_index(filename, self.listen_port, username)
            elif action == "3":
                self.list_files()
            elif action == "4":
                print("Logging out...")
                break
            else:
                print("Invalid option. Please try again.")
        
    def connect_menu(self):
        while True:
            print("\nConnect Options:")
            print("[1] List Active Peers")
            print("[2] Manage Incoming Requests")
            print("[3] Send Connection Request")
            print("[4] Back to Main Menu")

            connect_action = input("\nEnter your choice: ").strip()

            if connect_action == "1":
                self.list_peers()
            elif connect_action == "2":
                self.manage_incoming_requests()
            elif connect_action == "3":
                peer_username = input("Enter the peer's username: ")
                try:
                    self.send_command(f"REQUEST_PEER {peer_username}")
                    print("Connection request sent.")
                except Exception as e:
                    print(f"Failed to send connection request: {e}")
            elif connect_action == "4":
                break  # Exit the Connect menu
            else:
                print("Invalid option. Please try again.")

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
    
    client = Client(server_ip="127.0.0.1", port_number=49152)
    client.connect()  # If connection fails, exit

    client.start_listening() # Listen for incoming connections from other peers

    client.main_menu()
