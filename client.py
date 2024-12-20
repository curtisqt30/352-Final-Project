import socket
import os
import json
from tqdm import tqdm
import ssl
import threading
import time
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
            input(Fore.YELLOW + "Press Enter to continue...")
            return

        self.server_socket.send(f"REGISTER {username} {password}".encode())
        response = self.server_socket.recv(1024).decode()

        if response == "REGISTER_SUCCESS":
            print(Fore.GREEN + "Registration successful! Please login.")
        elif response == "USERNAME_TAKEN":
            print(Fore.RED + "Username already taken. Try again.")
        else:
            print(Fore.RED + "Registration failed. Try again.")
        
        input(Fore.YELLOW + "Press Enter to return to the menu...")

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
            # Set the user's directory
            self.local_files_dir = os.path.join("client_files", self.username)
            os.makedirs(self.local_files_dir, exist_ok=True)
            input(Fore.YELLOW + "Press Enter to continue...")
            return True
        elif response == "TOO_MANY_ATTEMPTS":
            print(Fore.RED + "Too many failed login attempts. Try again later.")
        else:
            print(Fore.RED + "Invalid credentials. Please try again.")
        
        input(Fore.YELLOW + "Press Enter to return to the main menu...")
        return False
        
    def logout(self):
        if self.username:
            self.server_socket.send(f"LOGOUT {self.username}".encode())
            response = self.server_socket.recv(1024).decode()
            if response == "LOGOUT_SUCCESS":
                print("Logged out successfully!")
        self.server_socket.close()
        exit(0)

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
        files = os.listdir(self.local_files_dir)
        if not files:
            print(Fore.YELLOW + f"No files found in your directory: {self.local_files_dir}")
            input(Fore.YELLOW + "Press Enter to return to the menu...")
            return

        print(Fore.CYAN + f"Files in your directory ({self.local_files_dir}):")
        for idx, file in enumerate(files, start=1):
            print(Fore.CYAN + f"[{idx}] {file}")

        try:
            choice = int(input("Enter the number of the file you want to index: ").strip())
            if choice < 1 or choice > len(files):
                print(Fore.RED + "Invalid choice. Please try again.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            filename = files[choice - 1]
            file_path = os.path.join(self.local_files_dir, filename)

            aes_key = generate_AES_key()
            encrypted_file_path = aes_encrypt_file(file_path, aes_key)
            save_key(aes_key, os.path.join(self.local_files_dir, f"{filename}_key.json"))  # Save AES key

            file_hash = hash_file(encrypted_file_path)

            # Send INDEX command with file hash
            self.server_socket.send(f"INDEX {self.username} {filename} {socket.gethostbyname(socket.gethostname())} 5000 {file_hash}".encode())
            response = self.server_socket.recv(1024).decode()
            print(f"Server response: {response}")

            if response == "INDEX_SUCCESS":
                print(Fore.GREEN + f"File '{filename}' indexed successfully!")
            else:
                print(Fore.RED + f"Failed to index file '{filename}'. Server response: {response}")
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a number.")
        except Exception as e:
            print(Fore.RED + f"Error indexing file: {e}")

        input(Fore.YELLOW + "Press Enter to return to the menu...")

    def decrypt_file(self):
        encrypted_file = input("Enter the path of the encrypted file: ").strip()
        aes_key = load_key(os.path.join(self.local_files_dir, f"{os.path.basename(encrypted_file)}_key.json"))
        if not aes_key:
            print(Fore.RED + "AES key not found for this file.")
            return

        try:
            decrypted_file_path = aes_decrypt_file(encrypted_file, aes_key)
            print(Fore.GREEN + f"File decrypted successfully: {decrypted_file_path}")
        except ValueError as e:
            print(Fore.RED + f"Decryption failed: {e}")

        input(Fore.YELLOW + "Press Enter to return to the menu...")

    def list_files(self):
        # List all files in the user's directory
        files = os.listdir(self.local_files_dir)
        if not files:
            print(Fore.YELLOW + f"No files found in your directory: {self.local_files_dir}")
        else:
            print(Fore.CYAN + f"Current files in your directory ({self.local_files_dir}):")
            for file in files:
                # Display each file with its type
                if file.endswith(".enc"):
                    print(Fore.GREEN + f"  {file} (Encrypted)")
                elif file.endswith(".json"):
                    print(Fore.MAGENTA + f"  {file} (Key File)")
                else:
                    print(Fore.WHITE + f"  {file} (Plaintext)")

        input(Fore.YELLOW + "Press Enter to return to the menu...")

    def search_file(self):
        query = input("Enter filename to search: ").strip()
        self.server_socket.send(f"SEARCH {query}".encode())
        try:
            response = self.server_socket.recv(4096).decode()
            files = json.loads(response)  # Parse JSON response

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

        input(Fore.YELLOW + "Press Enter to return to the menu...")

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

    def request_file(self, peer_ip, peer_port, filename):
        try:
            self.server_socket.send(f"FILE_REQUEST {self.username} {filename} {peer_ip}".encode())
            response = self.server_socket.recv(1024).decode()

            if response == "REQUEST_QUEUED":
                print(Fore.YELLOW + f"Request for '{filename}' has been sent. Waiting for approval...")
                self.wait_for_approval(peer_ip, peer_port, filename)
            elif response == "FILE_NOT_FOUND":
                print(Fore.RED + f"The file '{filename}' was not found on the peer's device.")
            elif response == "REQUEST_DENIED":
                print(Fore.RED + f"The peer denied your request for '{filename}'.")
            else:
                print(Fore.RED + f"Unexpected response: {response}")
        except Exception as e:
            print(Fore.RED + f"Error during file request: {e}")

    def wait_for_approval(self, peer_ip, peer_port, filename, timeout=60):
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self.server_socket.recv(1024).decode()
                if response == "READY":
                    print(Fore.GREEN + f"Request approved. Downloading '{filename}'...")
                    self.download_file(peer_ip, peer_port, filename)
                    return
                elif response == "DENIED":
                    print(Fore.RED + f"Request denied for '{filename}'.")
                    return
            except socket.timeout:
                pass  # Keep waiting
        print(Fore.RED + "Request timed out.")

    def manage_requests(self):
        self.server_socket.send(b"REQUEST_QUEUE")
        response = self.server_socket.recv(4096).decode()
        requests = json.loads(response)

        if not requests:
            print(Fore.YELLOW + "No pending requests.")
            input(Fore.YELLOW + "Press Enter to return to the menu...")
            return

        for idx, req in enumerate(requests, start=1):
            print(Fore.CYAN + f"[{idx}] {req['requester']} requests '{req['filename']}'")
        choice = input(Fore.CYAN + "Select a request to process (or 0 to cancel): ").strip()

        if choice.isdigit() and int(choice) > 0 and int(choice) <= len(requests):
            selected_request = requests[int(choice) - 1]
            approve = input(Fore.CYAN + f"Approve request for '{selected_request['filename']}'? (y/n): ").strip().lower()
            if approve == "y":
                self.server_socket.send(f"APPROVE {selected_request['requester']} {selected_request['filename']}".encode())
                print(Fore.GREEN + "Request approved.")
            else:
                self.server_socket.send(f"DENY {selected_request['requester']} {selected_request['filename']}".encode())
                print(Fore.RED + "Request denied.")
        else:
            print(Fore.YELLOW + "No request selected.")
        input(Fore.YELLOW + "Press Enter to return to the menu...")

    def serve_file(self, client_socket):
        try:
            # Receive command and filename from the client
            data = client_socket.recv(1024).decode()
            command, filename = data.split()

            if command == "REQUEST":
                file_path = os.path.join(self.local_files_dir, filename)

                # Check if the requested file exists
                if not os.path.exists(file_path):
                    client_socket.send(b"FILE_NOT_FOUND")
                    print(Fore.RED + f"File '{filename}' not found for transfer.")
                    return

                print(Fore.YELLOW + f"Incoming request for '{filename}' from {client_socket.getpeername()}.")

                # Confirm file transfer
                confirm = input(Fore.CYAN + f"Allow transfer of '{filename}'? (y/n): ").strip().lower()
                if confirm != 'y':
                    client_socket.send(b"REQUEST_DENIED")
                    print(Fore.RED + f"Transfer of '{filename}' denied.")
                    return

                # Encrypt the file
                aes_key = generate_AES_key()
                encrypted_file_path = aes_encrypt_file(file_path, aes_key)

                # Assume the peer's public key is available for encryption
                peer_public_key = self.peer_public_key  # Ensure this is defined elsewhere in the class
                aes_key_encrypted = rsa_encrypt(aes_key, peer_public_key)

                # Send READY signal and encrypted AES key
                client_socket.send(b"READY")
                client_socket.send(aes_key_encrypted)

                # Send the encrypted file in chunks
                with open(encrypted_file_path, "rb") as file:
                    print(Fore.GREEN + f"Sending file '{filename}'...")
                    while chunk := file.read(4096):
                        client_socket.send(chunk)
                    print(Fore.CYAN + f"File '{filename}' sent successfully.")
            else:
                print(Fore.RED + f"Invalid command received: {command}")
                client_socket.send(b"INVALID_COMMAND")
        except Exception as e:
            print(Fore.RED + f"Error during file transfer: {e}")
        finally:
            client_socket.close()

    def request_file_menu(self):
        try:
            # Request the list of active peers from the server
            self.server_socket.send(b"LIST_PEERS")
            response = self.server_socket.recv(4096).decode()
            peers = json.loads(response)

            if not peers:
                print(Fore.YELLOW + "No active peers found.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            while True:
                self.clear_screen()
                print(Fore.CYAN + "\n===================================")
                print(f"   REQUEST FILES FROM PEERS")
                print("===================================")

                # Display the list of peers
                peer_list = list(peers.items())
                for idx, (username, info) in enumerate(peer_list, start=1):
                    print(Fore.CYAN + f"[{idx}] {username} ({info['address']})")
                print(Fore.CYAN + "\n[0] 🔙 Back to Main Menu")
                print("===================================")

                peer_choice = input("Select a peer by number: ").strip()

                if not peer_choice.isdigit() or int(peer_choice) == 0:
                    break  # Return to main menu

                peer_choice = int(peer_choice) - 1
                if peer_choice < 0 or peer_choice >= len(peer_list):
                    print(Fore.RED + "Invalid choice. Please try again.")
                    input(Fore.YELLOW + "Press Enter to continue...")
                    continue

                selected_peer = peer_list[peer_choice]
                username, info = selected_peer

                while True:
                    self.clear_screen()
                    print(Fore.CYAN + f"\n===================================")
                    print(f"   FILES SHARED BY {username.upper()}")
                    print("===================================")

                    # Display the list of files shared by the selected peer
                    if not info["files"]:
                        print(Fore.YELLOW + "No files available from this peer.")
                        input(Fore.YELLOW + "Press Enter to return to the peer list...")
                        break

                    for idx, file in enumerate(info["files"], start=1):
                        print(Fore.CYAN + f"[{idx}] {file}")
                    print(Fore.CYAN + "\n[0] 🔙 Back to Peer List")
                    print("===================================")

                    file_choice = input("Select a file by number: ").strip()

                    if not file_choice.isdigit() or int(file_choice) == 0:
                        break  # Return to peer list

                    file_choice = int(file_choice) - 1
                    if file_choice < 0 or file_choice >= len(info["files"]):
                        print(Fore.RED + "Invalid choice. Please try again.")
                        input(Fore.YELLOW + "Press Enter to continue...")
                        continue

                    selected_file = info["files"][file_choice]
                    print(Fore.YELLOW + f"Requesting file '{selected_file}' from {username}...")
                    self.request_file(info["address"], 5000, selected_file)  # Adjust port if needed
                    input(Fore.GREEN + "Press Enter to return to the file list...")
        except json.JSONDecodeError:
            print(Fore.RED + "Error decoding server response. The data might be corrupted.")
        except Exception as e:
            print(Fore.RED + f"An unexpected error occurred: {e}")
        finally:
            input(Fore.YELLOW + "Press Enter to return to the menu...")

    def list_peers(self):
        try:
            self.server_socket.send(b"LIST_PEERS")
            response = self.server_socket.recv(4096).decode()
            peers = json.loads(response)

            if peers:
                print(Fore.GREEN + "Active peers and their files:")
                for username, info in peers.items():
                    print(Fore.CYAN + f"- {username} ({info['address']})")
                    for file in info["files"]:
                        print(Fore.WHITE + f"  - {file}")
            else:
                print(Fore.YELLOW + "No active peers found.")
        except json.JSONDecodeError:
            print(Fore.RED + "Error decoding server response. The data might be corrupted.")
        except Exception as e:
            print(Fore.RED + f"An unexpected error occurred: {e}")
        finally:
            input(Fore.YELLOW + "Press Enter to return to the menu...")

    def start_peer_listener(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((self.server_ip, self.server_port))
            server_socket.listen(5)
            print(Fore.GREEN + f"Peer listening on {self.server_ip}:{self.server_port}...")
            while True:
                client_socket, client_address = server_socket.accept()
                print(Fore.CYAN + f"Connection received from {client_address}")
                threading.Thread(target=self.serve_file, args=(client_socket,), daemon=True).start()
        except Exception as e:
            print(Fore.RED + f"Error starting peer listener: {e}")

    def view_pending_requests(self):
        try:
            self.server_socket.send(b"REQUEST_QUEUE")
            response = self.server_socket.recv(4096).decode()

            if not response:
                print(Fore.RED + "Error: Received empty response from server.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            try:
                requests = json.loads(response)
            except json.JSONDecodeError:
                print(Fore.RED + "Error: Received invalid JSON from server.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            if not requests:
                print(Fore.YELLOW + "No pending requests.")
            else:
                print(Fore.CYAN + "Pending Requests:")
                for idx, req in enumerate(requests, start=1):
                    print(Fore.CYAN + f"[{idx}] {req['requester']} requests '{req['filename']}'")

            input(Fore.YELLOW + "Press Enter to return to the menu...")
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}")
            input(Fore.YELLOW + "Press Enter to return to the menu...")

    def manage_requests_menu(self):
        while True:
            self.clear_screen()
            print(Fore.CYAN + "\n===================================")
            print("       MANAGE INCOMING REQUESTS")
            print("===================================")
            print("[1] View Pending Requests")
            print("[2] Approve/Deny Specific Requests")
            print("[3] Back to Main Menu")
            print("===================================")

            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.view_pending_requests()
            elif choice == "2":
                self.manage_requests()
            elif choice == "3":
                break
            else:
                print(Fore.RED + "Invalid choice. Try again.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")

        
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
            print("[4] 📜 List My Files")
            print("[5] 🟢 List Active Peers")
            print("[6] 📨 Manage Incoming Requests")
            print("[7] 🔙 Exit")
            print("===================================")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.index_file()
            elif choice == "2":
                self.search_file()
            elif choice == "3":
                self.request_file_menu()
            elif choice == "4":
                self.list_files()
            elif choice == "5":
                self.list_peers()
            elif choice == "6":
                self.manage_requests_menu()
            elif choice == "7":
                print(Fore.YELLOW + "Exiting client...")
                self.server_socket.close()
                break
            else:
                print(Fore.RED + "Invalid choice. Try again.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")

if __name__ == "__main__":
    client = Client()
    client.main_menu()