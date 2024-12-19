import socket
import os
import threading
import pwinput
from tqdm import tqdm
import json
import sys
import random
import logging

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
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

class Client:
    def __init__(self, server_ip="0.0.0.0", port_number=49152):
        self.server_ip = server_ip
        self.port_number = port_number
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_port = random.randint(49153, 65535)
        self.incoming_requests = []
        self.local_file_directory = "client_files"
        os.makedirs(self.local_file_directory, exist_ok=True)

    
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
        
    def initiate_peer_connection(self, username, peer_ip, peer_port):
        try:
            print(f"Attempting to connect to {username} at {peer_ip}:{peer_port}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
                peer_sock.connect((peer_ip, peer_port))
                print(f"Connected to {username}. Proceeding to file exchange...")
                self.file_exchange(username)
        except Exception as e:
            print(f"Failed to connect to {username} at {peer_ip}:{peer_port}. Error: {e}")
            
    def wait_for_peer_acceptance(self, peer_username, peer_ip, peer_port):
        try:
            print("Waiting for peer to accept the connection request...")
            self.cli_sock.settimeout(30)  # Wait for up to 30 seconds

            while True:
                try:
                    response = self.cli_sock.recv(1024).decode()
                    if response == "CONNECTION_ACCEPTED":
                        print(f"Peer '{peer_username}' accepted the connection. Starting file exchange...")
                        self.initiate_peer_connection(peer_username, peer_ip, peer_port)
                        break
                    elif response == "CONNECTION_REJECTED":
                        print(f"Peer '{peer_username}' rejected the connection.")
                        break
                    else:
                        print(f"Unexpected response: {response}")
                except socket.timeout:
                    print("Timed out waiting for peer's response. Returning to menu.")
                    break
        except Exception as e:
            print(f"Error waiting for peer acceptance: {e}")
        finally:
            self.cli_sock.settimeout(None)
            
    def accept_incoming_request(self):
        if not self.incoming_requests:
            print("\nNo incoming requests to accept.")
            return

        try:
            request_index = int(input("Enter the index of the request to accept: ").strip())
            if request_index < 0 or request_index >= len(self.incoming_requests):
                print("Invalid index. Returning to menu.")
                return

            conn, addr = self.incoming_requests[request_index]
            conn.send("CONNECTION_ACCEPTED".encode())
            print(f"Connection from {addr} accepted.")
            self.incoming_requests.pop(request_index)
        except Exception as e:
            print(f"Error accepting request: {e}")
            
    def reject_incoming_request(self):
        if not self.incoming_requests:
            print("\nNo incoming requests to reject.")
            return

        try:
            request_index = int(input("Enter the index of the request to reject: ").strip())
            if request_index < 0 or request_index >= len(self.incoming_requests):
                print("Invalid index. Returning to menu.")
                return

            conn, addr = self.incoming_requests[request_index]
            conn.send("CONNECTION_REJECTED".encode())
            print(f"Connection request from {addr} rejected.")
            self.incoming_requests.pop(request_index)
        except Exception as e:
            print(f"Error rejecting request: {e}")
    
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

    def handle_request_peer(self, client_socket, target_username):
        # Find the target peer in the list of connected clients
        target_peer = self.find_peer_by_username(target_username)

        if target_peer:
            # Notify the target peer of the incoming connection request
            target_peer.socket.send(f"CONNECTION_REQUEST from {client_socket.username}".encode())
            client_socket.send(f"PEER_FOUND {target_peer.username} {target_peer.ip} {target_peer.listen_port}".encode())
        else:
            client_socket.send("PEER_NOT_FOUND".encode())


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
            file_path = os.path.join(self.local_file_directory, filename)
            if not os.path.exists(file_path):
                conn.send(f"ERROR: File not found: {filename}".encode())
                return
            with open(file_path, "rb") as f:
                print(f"Sending file: {filename}")
                while chunk := f.read(1024):
                    conn.send(chunk)
            print(f"File {filename} sent successfully.")
        except Exception as e:
            print(f"Error sending file: {e}")

    def send_file_size(self, conn, filename):
        try:
            file_path = os.path.join(self.local_file_directory, filename)
            if not os.path.exists(file_path):
                conn.send(f"ERROR: File not found: {filename}".encode())
                return
            file_size = os.path.getsize(file_path)
            conn.send(str(file_size).encode())
        except Exception as e:
            print(f"Error sending file size: {e}")

    def request_file_from_peer(self, peer_ip, peer_port, filename):
        try:
            print(f"Attempting to connect to peer {peer_ip}:{peer_port}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
                peer_sock.connect((peer_ip, peer_port))

                print("Requesting file size...")
                peer_sock.send(f"GET_SIZE {filename}".encode())
                file_size = int(peer_sock.recv(1024).decode())

                print(f"File size received: {file_size} bytes.")
                file_path = os.path.join(self.local_file_directory, f"downloaded_{filename}")
                with open(file_path, "wb") as f, tqdm(total=file_size, unit="B", unit_scale=True) as pbar:
                    print(f"Downloading {filename} from {peer_ip}:{peer_port}...")
                    while data := peer_sock.recv(1024):
                        f.write(data)
                        pbar.update(len(data))
                print(f"File {filename} downloaded successfully.")
        except Exception as e:
            print(f"Failed to request file from peer: {e}")

    def store_incoming_request(self, conn, addr):
        print(f"Storing incoming connection request from {addr}.")
        self.incoming_requests.append((conn, addr))
        print(f"Current incoming requests: {self.incoming_requests}")

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

    def list_incoming_requests(self):
        if not self.incoming_requests:
            print("\nNo incoming requests.")
        else:
            print("\nIncoming Requests:")
            for idx, (conn, addr) in enumerate(self.incoming_requests):
                print(f"{idx}. From {addr}")

    def clear_incoming_requests(self):
        command = "CLEAR_INCOMING_REQUESTS"
        response = self.send_command(command)
        if response != "INCOMING_REQUESTS_CLEARED":
            print("Failed to clear incoming requests.")

    def accept_incoming_request(self):
        if not self.incoming_requests:
            print("\nNo incoming requests to accept.")
            return

        try:
            request_index = int(input("\nEnter the index of the request to accept: ").strip())

            if request_index < 0 or request_index >= len(self.incoming_requests):
                print("Invalid index. Returning to menu.")
                return

            conn, addr = self.incoming_requests[request_index]
            print(f"Accepting connection from {addr}")
            conn.send("CONNECTION_ACCEPTED".encode())  # Send acceptance message
            print(f"Connection with {addr} accepted.")

            # Remove the handled request from the list
            del self.incoming_requests[request_index]

        except ValueError:
            print("Invalid input. Returning to menu.")

    # User Interface
    def main_menu(self):
        while True:
            print("\n==============================")
            print("          MAIN MENU           ")
            print("==============================")
            print("[1] 🔑 Login")
            print("[2] 📝 Register")
            print("[3] ❌ Exit")
            print("==============================")

            choice = input("Enter your choice (1-3): ").strip()

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
            print("\n===================================")
            print(f"   WELCOME, {username.upper()}!")
            print("===================================")
            print("[1] 🔗 Connect")
            print("[2] 📤 Index a File")
            print("[3] 📂 List Indexed Files")
            print("[4] 🔙 Logout")
            print("===================================")

            action = input("Enter your choice (1-4): ").strip()

            if action == "1":
                print("\nMoving to Connect Menu...")
                self.connect_menu()
            elif action == "2":
                filename = input("Enter file path to upload: ")
                self.handle_index(filename, self.listen_port, username)
            elif action == "3":
                self.list_files()
            elif action == "4":
                print("\nLogging out...")
                break
            else:
                print("\nInvalid option. Please try again.")
            
    def connect_menu(self):
        while True:
            print("\n==============================")
            print("        CONNECT MENU          ")
            print("==============================")
            print("[1] 🟢 List Active Peers")
            print("[2] 📩 Manage Incoming Requests")
            print("[3] 🤝 Send Connection Request")
            print("[4] 🔙 Back to Main Menu")
            print("==============================")

            connect_action = input("Enter your choice (1-4): ").strip()

            if connect_action == "1":
                self.list_peers()
            elif connect_action == "2":
                print("\nMoving to Manage Incoming Request Menu...")
                self.manage_incoming_requests()
            elif connect_action == "3":
                peer_username = input("Enter the peer's username: ")
                print(f"\nconnection request to {peer_username}...")
                response = self.send_command(f"REQUEST_PEER {peer_username}")

                if response.startswith("PEER_NOT_FOUND"):
                    print(f"Peer '{peer_username}' not found. Returning to menu.")
                    continue
                elif response.startswith("PEER_FOUND"):
                    _, username, peer_ip, peer_port = response.split()
                    peer_port = int(peer_port)

                    print(f"Peer '{username}' found at {peer_ip}:{peer_port}. Waiting for acceptance...")
                    self.wait_for_peer_acceptance(peer_username, peer_ip, peer_port)
                else:
                    print(f"Unexpected response: {response}")
            elif connect_action == "4":
                print("\nReturning to Main Menu...")
                break
            else:
                print("\nInvalid option. Please try again.")

    def manage_incoming_requests(self):
        while True:
            print("\n===================================")
            print("  MANAGE INCOMING REQUESTS MENU   ")
            print("===================================")
            print("[1] 📋 List Incoming Requests")
            print("[2] ✅ Accept Incoming Request")
            print("[3] ❌ Reject Incoming Request")
            print("[4] 🔙 Return to Previous Menu")
            print("===================================")

            try:
                request_choice = int(input("Enter your choice (1-4): ").strip())

                if request_choice == 1:
                    self.list_incoming_requests()
                elif request_choice == 2:
                    self.accept_incoming_request()
                elif request_choice == 3:
                    self.reject_incoming_request()
                elif request_choice == 4:
                    print("\nReturning to previous menu...")
                    return
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")
                
    def file_exchange(self, peer_username):
        print(f"Starting file exchange with {peer_username}...")
        while True:
            print("\nFile Exchange Options:")
            print("[1] Send a File")
            print("[2] Request a File")
            print("[3] End File Exchange")

            exchange_action = input("\nEnter your choice: ").strip()

            if exchange_action == "1":
                filename = input("Enter the file name to send: ")
                self.send_file(self.cli_sock, filename)  # Update as needed for specific socket
            elif exchange_action == "2":
                filename = input("Enter the file name to request: ")
                peer_ip = input("Enter the peer's IP address: ")
                peer_port = int(input("Enter the peer's port: "))
                self.request_file_from_peer(peer_ip, peer_port, filename)
            elif exchange_action == "3":
                print("Ending file exchange...")
                break
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
