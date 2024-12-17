import socket
import os
import json
from tqdm import tqdm
import ssl
import threading
import pwinput
from colorama import Fore, Style, init
from util import (
    hash_file,
    aes_encrypt_file,
    aes_decrypt_file,
    rsa_encrypt,
    rsa_decrypt,
    verify_signature_rsa,
    generate_AES_key,
    save_key,
    load_key,
)

init(autoreset=True)

SERVER_PUBLIC_KEY = None  # Retrieve dynamically after connecting

class Client:
    def __init__(self, server_ip="127.0.0.1", server_port=49152):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_files_dir = "client_files"
        self.username = None  # To track logged-in user
        os.makedirs(self.local_files_dir, exist_ok=True)

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def connect_to_server(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("server_cert.pem")
            self.server_socket = context.wrap_socket(self.server_socket, server_hostname=self.server_ip)
            self.server_socket.connect((self.server_ip, self.server_port))
            print(Fore.GREEN + f"Connected securely to server at {self.server_ip}:{self.server_port}")
        except ssl.SSLError as ssl_err:
            print(Fore.RED + f"SSL Error: {ssl_err}. Ensure the server certificate is valid and accessible.")
            exit(1)
        except FileNotFoundError:
            print(Fore.RED + "Certificate file not found. Please check 'server_cert.pem'.")
            exit(1)
        except Exception as e:
            print(Fore.RED + f"Failed to connect to server: {e}")
            exit(1)

    def send_file_with_hash(self, peer_socket, file_path):
        aes_key = generate_AES_key()
        encrypted_file_path = aes_encrypt_file(file_path, aes_key)
        save_key(aes_key, f"{os.path.basename(file_path)}_key.json")

        file_hash = hash_file(encrypted_file_path)  # Calculate hash of the encrypted file

        # Send file hash first
        peer_socket.send(f"HASH {file_hash}".encode())

        # Send the encrypted file
        with open(encrypted_file_path, "rb") as file:
            peer_socket.sendall(file.read())
        print(f"Encrypted file and hash sent: {encrypted_file_path}")

    def register(self):
        self.clear_screen()
        print(Fore.CYAN + "========== Register ==========")
        username = input("Enter a new username: ").strip()
        password = pwinput.pwinput("Enter a new password: ", mask="*").strip() 
        confirm_password = pwinput.pwinput("Confirm your password: ", mask="*").strip()

        if password != confirm_password:
            print(Fore.RED + "Passwords do not match. Please try again.")
            return

        self.server_socket.send(f"REGISTER {username} {password}".encode())
        response = self.server_socket.recv(1024).decode()

        if response == "REGISTER_SUCCESS":
            print(Fore.GREEN + "Registration successful! Please login.")
        elif response == "USERNAME_TAKEN":
            print(Fore.RED + "Username already taken. Try again.")
        else:
            print(Fore.RED + "Registration failed. Try again.")

    def login(self):
        self.clear_screen()
        print(Fore.CYAN + "========== Login ==========")
        username = input("Enter your username: ").strip()
        password = pwinput.pwinput("Enter your password: ", mask="*").strip()

        self.server_socket.send(f"LOGIN {username} {password}".encode())
        response = self.server_socket.recv(1024).decode()

        if response == "LOGIN_SUCCESS":
            print(Fore.GREEN + "Login successful!")
            self.username = username
            return True
        else:
            print(Fore.RED + "Invalid credentials. Please try again.")
            return False

    def ensure_login(self):
        while not self.username:
            self.clear_screen()
            print(Fore.MAGENTA + "\n==============================")
            print("          MAIN MENU           ")
            print("==============================")
            print("[1] 🔑 Login")
            print("[2] 📝 Register")
            print("[3] ❌ Exit")
            print("==============================")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                if self.login():
                    break
            elif choice == "2":
                self.register()
            elif choice == "3":
                self.server_socket.close()
                exit(0)
            else:
                print(Fore.RED + "Invalid choice. Try again.")

    def index_file(self):
        filename = input("Enter the filename to index: ").strip()
        file_path = os.path.join(self.local_files_dir, filename)

        if not os.path.exists(file_path):
            print(Fore.RED + f"File '{filename}' does not exist. Please provide a valid file.")
            return

        # Attempt to read the file and encrypt it
        try:
            aes_key = generate_AES_key()
            encrypted_file_path = aes_encrypt_file(file_path, aes_key)
            save_key(aes_key, f"{filename}_key.json")  # Save AES key for later decryption
            file_hash = hash_file(encrypted_file_path)

            # Send metadata to the server
            self.server_socket.send(f"INDEX {self.username} {filename} {socket.gethostbyname(socket.gethostname())} 5000".encode())
            response = self.server_socket.recv(1024).decode()

            if response == "INDEX_SUCCESS":
                print(Fore.GREEN + f"File '{filename}' indexed successfully!")
            else:
                print(Fore.RED + f"Failed to index file '{filename}'. Server response: {response}")
        except Exception as e:
            print(Fore.RED + f"Error indexing file '{filename}': {e}")

    def decrypt_file(self):
        encrypted_file = input("Enter the path of the encrypted file: ").strip()
        aes_key = load_key(f"{os.path.basename(encrypted_file)}_key.json")
        if not aes_key:
            print("AES key not found for this file.")
            return

        try:
            decrypted_file_path = aes_decrypt_file(encrypted_file, aes_key)
            print(f"File decrypted successfully: {decrypted_file_path}")
        except ValueError as e:
            print(f"Decryption failed: {e}")

    def search_file(self):
        query = input("Enter filename to search: ").strip()
        self.server_socket.send(f"SEARCH {query}".encode())
        try:
            response = self.server_socket.recv(1024).decode()
            files = json.loads(response)

            if files:
                print(Fore.GREEN + f"Files matching '{query}':")
                for file in files:
                    print(Fore.CYAN + f"- {file['filename']} (Peer: {file['ip']}:{file['port']})")
            else:
                print(Fore.YELLOW + f"No files found matching the keyword '{query}'.")
        except json.JSONDecodeError:
            print(Fore.RED + "Error decoding server response. The data might be corrupted.")
        except Exception as e:
            print(Fore.RED + f"An unexpected error occurred during search: {e}")

    def send_file(self, peer_socket, file_path):
        aes_key = generate_AES_key()
        encrypted_file_path = aes_encrypt_file(file_path, aes_key)
        save_key(aes_key, f"{os.path.basename(file_path)}_key.json")

        with open(encrypted_file_path, "rb") as file:
            peer_socket.sendall(file.read())
        print(f"Encrypted file sent: {encrypted_file_path}")

    def receive_file(self, file_path):
        aes_key = load_key(f"{os.path.basename(file_path)}_key.json")
        if not aes_key:
            print("AES key not available for decryption.")
            return

        decrypted_file_path = aes_decrypt_file(file_path, aes_key)
        print(f"Received file decrypted: {decrypted_file_path}")

    def validate_file_index(self):
        filename = input("Enter the filename to validate: ").strip()
        self.server_socket.send(f"VERIFY_INDEX {filename}".encode())
        response = self.server_socket.recv(1024).decode()

        if response == "INDEX_VALID":
            print(Fore.GREEN + f"The file index for '{filename}' is valid.")
        elif response == "FILE_NOT_FOUND":
            print(Fore.YELLOW + f"No index entry found for '{filename}'. It might not be indexed yet.")
        elif response == "INDEX_INVALID":
            print(Fore.RED + f"The file index for '{filename}' is invalid or tampered.")
        else:
            print(Fore.RED + f"Unexpected server response: {response}")

    def request_file(self, peer_ip, peer_port, filename):
        try:
            # Establish secure connection to the peer
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("server_cert.pem")
            peer_socket = socket.create_connection((peer_ip, peer_port))
            secure_peer_socket = context.wrap_socket(peer_socket, server_hostname=peer_ip)

            # Request file from the peer
            secure_peer_socket.send(f"REQUEST {filename}".encode())
            response = secure_peer_socket.recv(1024).decode()

            if response == "FILE_NOT_FOUND":
                print(Fore.YELLOW + f"Peer does not have the file '{filename}'.")
            elif response.startswith("READY"):
                aes_key_encrypted = secure_peer_socket.recv(256)  # Receive encrypted AES key
                aes_key = rsa_decrypt(aes_key_encrypted, self.private_key)

                # Receive file in chunks
                file_path = os.path.join(self.local_files_dir, filename)
                with open(file_path, "wb") as file:
                    print(Fore.GREEN + f"Receiving file '{filename}' from {peer_ip}:{peer_port}...")
                    while True:
                        chunk = secure_peer_socket.recv(4096)
                        if not chunk:
                            break
                        file.write(chunk)
                    print(Fore.CYAN + f"File '{filename}' received successfully.")

                # Decrypt the file
                decrypted_file_path = aes_decrypt_file(file_path, aes_key)
                print(Fore.GREEN + f"File '{filename}' decrypted and saved as '{decrypted_file_path}'.")
            else:
                print(Fore.RED + "Unexpected response from peer.")
        except Exception as e:
            print(Fore.RED + f"Error during file request: {e}")
        finally:
            secure_peer_socket.close()

    def serve_file(self, client_socket):
        try:
            data = client_socket.recv(1024).decode()
            command, filename = data.split()

            if command == "REQUEST":
                file_path = os.path.join(self.local_files_dir, filename)
                if not os.path.exists(file_path):
                    client_socket.send(b"FILE_NOT_FOUND")
                    return

                # Encrypt the file
                aes_key = generate_AES_key()
                encrypted_file_path = aes_encrypt_file(file_path, aes_key)

                # Send AES key encrypted with the recipient's public key
                aes_key_encrypted = rsa_encrypt(aes_key, self.peer_public_key)  # Assumes you have the peer's public key
                client_socket.send(b"READY")
                client_socket.send(aes_key_encrypted)

                # Send file in chunks
                with open(encrypted_file_path, "rb") as file:
                    print(Fore.GREEN + f"Sending file '{filename}'...")
                    while chunk := file.read(4096):
                        client_socket.send(chunk)
                    print(Fore.CYAN + f"File '{filename}' sent successfully.")
        except Exception as e:
            print(Fore.RED + f"Error serving file: {e}")

    def request_file_menu(self):
        try:
            peer_ip = input("Enter the peer's IP address: ").strip()
            if not peer_ip:
                print(Fore.RED + "Peer IP address cannot be empty.")
                return

            while True:
                peer_port_input = input("Enter the peer's port: ").strip()
                if not peer_port_input.isdigit():  # Validate numeric input
                    print(Fore.RED + "Port must be a valid number. Please try again.")
                    continue
                peer_port = int(peer_port_input)
                break

            filename = input("Enter the filename you want to request: ").strip()
            if not filename:
                print(Fore.RED + "Filename cannot be empty.")
                return

            print(Fore.YELLOW + f"Attempting to request file '{filename}' from {peer_ip}:{peer_port}...")

            # Connect to the peer and request the file
            self.request_file_from_peer(peer_ip, peer_port, filename)

        except ValueError as e:
            print(Fore.RED + f"Invalid input: {e}")
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}")

    def start_peer_listener(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.server_ip, self.server_port))
        server_socket.listen(5)
        print(Fore.GREEN + f"Peer listening on {self.server_ip}:{self.server_port}...")

        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=self.serve_file, args=(client_socket,), daemon=True).start()

    def main_menu(self):
        self.connect_to_server()
        self.ensure_login()
        threading.Thread(target=self.start_peer_listener, daemon=True).start()  # Start serving files in the background

        while True:
            self.clear_screen()
            print(Fore.CYAN + "\n===================================")
            print(f"   WELCOME, {self.username.upper()}!")
            print("===================================")
            print("[1] 📤 Index File")
            print("[2] 📂 Search File")
            print("[3] 🔄 Request File from Peer")
            print("[4] 🛡️  Validate File Index")
            print("[5] 🔙 Exit")
            print("===================================")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.index_file()
            elif choice == "2":
                self.search_file()
            elif choice == "3":
                self.request_file_menu()
            elif choice == "4":
                self.validate_file_index()
            elif choice == "5":
                print(Fore.YELLOW + "Exiting client...")
                self.server_socket.close()
                break
            else:
                print(Fore.RED + "Invalid choice. Try again.")

if __name__ == "__main__":
    client = Client()
    client.main_menu()

