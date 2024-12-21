import socket
import os
import json
from tqdm import tqdm
import ssl
import threading
import time
import pwinput
import random
import base64
import logging
from colorama import Fore, Style, init
from util import (
    hash_file,
    aes_encrypt_file,
    aes_decrypt_file,
    generate_AES_key,
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
    sign_data_dsa,
    generate_DSA_keypair,
    verify_signature_dsa,
    save_key,
    load_key,
)

# Initialize logging and colorama
logging.basicConfig(
    filename="client.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
init(autoreset=True)

SERVER_PUBLIC_KEY = None

class Client:
    def __init__(self, server_ip="127.0.0.1", server_port=49152):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_files_dir = "client_files"
        self.username = None
        self.signature_algorithm = None
        os.makedirs(self.local_files_dir, exist_ok=True)

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def connect_to_server(self):
        retries = 3
        for attempt in range(retries):
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations("server_cert.pem")
                self.server_socket = context.wrap_socket(self.server_socket, server_hostname=self.server_ip)
                self.server_socket.connect((self.server_ip, self.server_port))
                print(Fore.GREEN + f"Connected securely to server at {self.server_ip}:{self.server_port}")
                return
            except ssl.SSLError as ssl_err:
                print(Fore.RED + f"SSL Error: {ssl_err}. Retrying ({attempt + 1}/{retries})...")
                time.sleep(1)
            except Exception as e:
                print(Fore.RED + f"Failed to connect to server: {e}")
                time.sleep(1)
        print(Fore.RED + "Failed to connect to the server after multiple attempts.")
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

    def sign_file(self, file_path, private_key):
        file_hash = hash_file(file_path).encode()
        if self.signature_algorithm == "RSA":
            return sign_data_rsa(file_hash, private_key)
        elif self.signature_algorithm == "DSA":
            return sign_data_dsa(file_hash, private_key)
        else:
            raise ValueError("Invalid signature algorithm selected.")

    def verify_file_signature(self, file_path, signature, public_key):
        file_hash = hash_file(file_path).encode()
        if self.signature_algorithm == "RSA":
            return verify_signature_rsa(file_hash, signature, public_key)
        elif self.signature_algorithm == "DSA":
            return verify_signature_dsa(file_hash, signature, public_key)
        else:
            raise ValueError("Invalid signature algorithm selected.")

    def select_signature_algorithm(self):
            while True:
                self.clear_screen()
                print(Fore.CYAN + "Select Digital Signature Algorithm:")
                print(Fore.CYAN + "[1] RSA")
                print(Fore.CYAN + "[2] DSA")
                choice = input("Enter your choice: ").strip()
                if choice == "1":
                    self.signature_algorithm = "RSA"
                    print(Fore.GREEN + "RSA selected for digital signatures.")
                    break
                elif choice == "2":
                    self.signature_algorithm = "DSA"
                    print(Fore.GREEN + "DSA selected for digital signatures.")
                    break
                else:
                    print(Fore.RED + "Invalid choice. Please select 1 or 2.")
                input(Fore.YELLOW + "Press Enter to continue...")

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

        # Select signature algorithm
        self.select_signature_algorithm()

        # Generate keys based on the selected algorithm
        try:
            if self.signature_algorithm == "RSA":
                private_key, public_key = generate_RSA_keypair()
            elif self.signature_algorithm == "DSA":
                private_key, public_key = generate_DSA_keypair()
            else:
                raise ValueError("Invalid signature algorithm selected.")

            # Save the keys
            private_key_path = f"{username}_private.pem"
            public_key_path = f"{username}_public.pem"

            with open(private_key_path, "wb") as priv_file:
                priv_file.write(private_key.export_key())
            with open(public_key_path, "wb") as pub_file:
                pub_file.write(public_key.export_key())

            print(Fore.GREEN + f"Keys generated and saved as {private_key_path} and {public_key_path}.")
        except Exception as e:
            print(Fore.RED + f"Error generating keys: {e}")
            input(Fore.YELLOW + "Press Enter to return to the menu...")
            return

        # Send registration details to the server
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
            print(Fore.YELLOW + "No files found in your directory.")
            return

        print(Fore.CYAN + "Files in your directory:")
        for idx, file in enumerate(files, start=1):
            print(Fore.CYAN + f"[{idx}] {file}")
        
        try:
            choice = int(input("Select a file to index: ").strip()) - 1
            file_path = os.path.join(self.local_files_dir, files[choice])

            # Ensure the private key is loaded correctly
            private_key = load_key(f"{self.username}_private.pem")
            if private_key is None:
                print(Fore.RED + "Error: Private key not found. Please ensure you are registered.")
                return

            aes_key = generate_AES_key()
            encrypted_file_path = aes_encrypt_file(file_path, aes_key)

            # Sign the file hash
            signature = self.sign_file(encrypted_file_path, private_key)

            # Send index data to server
            self.server_socket.send(json.dumps({
                "command": "INDEX",
                "username": self.username,
                "filename": os.path.basename(file_path),
                "file_hash": hash_file(encrypted_file_path),
                "aes_key": base64.b64encode(aes_key).decode(),
                "signature": base64.b64encode(signature).decode()
            }).encode())

            response = self.server_socket.recv(1024).decode()
            if response == "INDEX_SUCCESS":
                print(Fore.GREEN + "File indexed successfully.")
            else:
                print(Fore.RED + "Failed to index file.")
        except FileNotFoundError:
            print(Fore.RED + "Error: Selected file not found.")
        except ValueError as ve:
            print(Fore.RED + f"Error: {ve}")
        except Exception as e:
            print(Fore.RED + f"Unexpected error: {e}")
        finally:
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
        # List files in the user's directory.
        files = os.listdir(self.local_files_dir)
        if not files:
            print(Fore.YELLOW + f"No files found in your directory: {self.local_files_dir}")
        else:
            print(Fore.CYAN + f"Files in your directory ({self.local_files_dir}):")
            for file in files:
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
            logging.info(f"Requesting file '{filename}' from {peer_ip}:{peer_port}.")
            self.server_socket.send(f"FILE_REQUEST {self.username} {filename} {peer_ip}".encode())
            response = self.server_socket.recv(1024).decode()
            logging.info(f"Server response: {response}")
            if response == "REQUEST_QUEUED":
                print(Fore.YELLOW + f"Request for '{filename}' has been sent. Waiting for approval...")
                self.wait_for_approval(peer_ip, peer_port, filename)
            else:
                logging.warning(f"Unexpected response from server: {response}")
        except Exception as e:
            logging.error(f"Error during file request: {e}")
            print(Fore.RED + f"Error during file request: {e}")

    def download_file(self, peer_ip, peer_port, filename, retries=3, delay=2):
        for attempt in range(retries):
            try:
                logging.info(f"Attempt {attempt + 1}: Connecting to {peer_ip}:{peer_port} for file '{filename}'.")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as file_socket:
                    file_socket.connect((peer_ip, int(peer_port)))
                    logging.info(f"Connected to {peer_ip}:{peer_port}. Requesting file '{filename}'.")
                    file_socket.send(f"REQUEST {filename}".encode())

                    response = file_socket.recv(1024).decode().strip()
                    logging.info(f"Received response from peer: {response}")

                    if response.startswith("READY"):
                        logging.info(f"Peer is ready. Starting download for '{filename}'.")
                        file_path = os.path.join(self.local_files_dir, filename)
                        with open(file_path, "wb") as file:
                            while True:
                                chunk = file_socket.recv(4096)
                                if not chunk:
                                    logging.info(f"Download completed for '{filename}'.")
                                    break
                                file.write(chunk)
                                logging.debug(f"Received chunk of size {len(chunk)} for '{filename}'.")
                        print(Fore.GREEN + f"File '{filename}' downloaded successfully.")
                        return
                    elif response == "FILE_NOT_FOUND":
                        logging.error(f"File '{filename}' not found on peer's system.")
                        print(Fore.RED + f"File '{filename}' not found on peer's system.")
                        return
                    else:
                        logging.warning(f"Unexpected response: {response}")
            except ConnectionRefusedError:
                logging.warning(f"Attempt {attempt + 1}: Connection refused by {peer_ip}:{peer_port}.")
                time.sleep(delay)
            except Exception as e:
                logging.error(f"Error during attempt {attempt + 1} to download '{filename}': {e}")
        logging.error(f"Failed to download '{filename}' after {retries} attempts.")
        print(Fore.RED + f"Failed to download '{filename}' after {retries} attempts.")

    def wait_for_approval(self, peer_ip, peer_port, filename, timeout=60):
        start_time = time.time()
        logging.info(f"Waiting for approval to download '{filename}' from {peer_ip}:{peer_port}.")
        while time.time() - start_time < timeout:
            try:
                response = self.server_socket.recv(1024).decode()
                logging.info(f"Received response: {response}")
                if response.startswith("READY"):
                    ready_filename = response.split(" ", 1)[1]
                    if ready_filename == filename:
                        logging.info(f"Approval received for '{filename}'. Initiating download.")
                        print(Fore.GREEN + f"Request approved. Downloading '{filename}'...")
                        self.download_file(peer_ip, peer_port, filename)
                        return
                elif response == "DENIED":
                    logging.warning(f"Request for '{filename}' was denied.")
                    print(Fore.RED + f"Request denied for '{filename}'.")
                    return
            except socket.timeout:
                logging.warning("Timeout while waiting for approval.")
            except Exception as e:
                logging.error(f"Error while waiting for approval for '{filename}': {e}")
        logging.error(f"Request for '{filename}' timed out.")
        print(Fore.RED + "Request timed out.")

    def manage_requests(self):
        try:
            # Send request to the server for pending requests
            self.server_socket.send(b"REQUEST_QUEUE")
            response = self.server_socket.recv(4096).decode()

            # Parse the response from the server
            if not response.strip():
                logging.info("No pending requests received.")
                print(Fore.YELLOW + "No pending requests.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            try:
                pending_requests = json.loads(response)  # Parse JSON response
            except json.JSONDecodeError:
                logging.error("Failed to decode server response. Possibly corrupted or empty.")
                print(Fore.RED + "Error decoding server response. Try again later.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            if not pending_requests:
                logging.info("No pending requests found.")
                print(Fore.YELLOW + "No pending requests.")
                input(Fore.YELLOW + "Press Enter to return to the menu...")
                return

            # Display pending requests
            print(Fore.CYAN + "Pending Requests:")
            for idx, req in enumerate(pending_requests, start=1):
                print(Fore.CYAN + f"[{idx}] {req['requester']} requests '{req['filename']}'")

            choice = input(Fore.CYAN + "Select a request to process (or 0 to cancel): ").strip()

            if choice.isdigit() and int(choice) > 0 and int(choice) <= len(pending_requests):
                selected_request = pending_requests[int(choice) - 1]
                approve = input(Fore.CYAN + f"Approve request for '{selected_request['filename']}'? (y/n): ").strip().lower()
                if approve == "y":
                    self.server_socket.send(
                        f"APPROVE_REQUEST {selected_request['filename']} {selected_request['requester']}".encode()
                    )
                    print(Fore.GREEN + "Request approved.")
                else:
                    self.server_socket.send(
                        f"DENY_REQUEST {selected_request['filename']} {selected_request['requester']}".encode()
                    )
                    print(Fore.RED + "Request denied.")

            else:
                print(Fore.YELLOW + "No valid request selected.")
            input(Fore.YELLOW + "Press Enter to return to the menu...")

        except Exception as e:
            logging.error(f"Error in manage_requests: {e}")
            print(Fore.RED + f"An error occurred: {e}")
            input(Fore.YELLOW + "Press Enter to return to the menu...")

    def serve_file(self, client_socket):
        try:
            data = client_socket.recv(1024).decode()
            logging.info(f"Received command: {data}")
            command, filename = data.split()

            if command == "REQUEST":
                file_path = os.path.join(self.local_files_dir, filename)
                if not os.path.exists(file_path):
                    logging.warning(f"Requested file '{filename}' not found.")
                    client_socket.send(b"FILE_NOT_FOUND")
                    return

                logging.info(f"Preparing to serve file '{filename}'.")
                client_socket.send(b"READY")

                with open(file_path, "rb") as file:
                    while chunk := file.read(4096):
                        client_socket.send(chunk)
                        logging.debug(f"Sent chunk of size {len(chunk)} for '{filename}'.")
                logging.info(f"File '{filename}' sent successfully.")
            else:
                logging.warning(f"Invalid command received: {command}.")
                client_socket.send(b"INVALID_COMMAND")
        except Exception as e:
            logging.error(f"Error during serve_file: {e}")
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
                    self.request_file(info["address"], info["port"], selected_file)
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
            while True:
                try:
                    # Bind to a random port in the range 50000-65535
                    port = random.randint(50000, 65535)
                    server_socket.bind((self.server_ip, port))
                    self.peer_port = port
                    break
                except OSError:
                    continue  # Retry with a different port

            server_socket.listen(5)
            logging.info(f"Peer listener running on {self.server_ip}:{self.peer_port}")

            # Notify server about the new port
            self.server_socket.send(f"UPDATE_PORT {self.username} {self.peer_port}".encode())
            response = self.server_socket.recv(1024).decode()
            if response != "PORT_UPDATED":
                logging.error("Server failed to update peer port.")
                return

            while True:
                client_socket, client_address = server_socket.accept()
                logging.info(f"Connection received from {client_address}")
                threading.Thread(target=self.serve_file, args=(client_socket,), daemon=True).start()
        except Exception as e:
            logging.error(f"Error starting peer listener: {e}")

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
        self.select_signature_algorithm()
        self.connect_to_server()
        self.ensure_login()
        
        # Start peer listener
        threading.Thread(target=self.start_peer_listener, daemon=True).start()

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