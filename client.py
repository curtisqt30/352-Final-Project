import socket
import os
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
    def __init__(self, server_ip="0.0.0.0", port_number=5000):
        self.server_ip = server_ip
        self.port_number = port_number
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self): # establish connection with the server using the server_ip and port_number
        try:
            self.cli_sock.connect((self.server_ip, self.port_number))
            print(f"Connected to server {self.server_ip} on port {self.port_number}")
        except Exception as e:
            print(f"Failed to connect: {e}")

    def disconnect(self): # close the socket connection to the server
        self.cli_sock.close()
        print("Disconnected from server.")

    def send_command(self, command): # Send commands to the server.
        try:
            self.cli_sock.send(command.encode())
            response = self.cli_sock.recv(1024).decode()
            print(f"Server response: {response}")
            return response
        except Exception as e:
            print(f"Error sending command: {e}")
            return None

    def handle_index(self, filename, port): # send an index command to server to register a file to share
        if not os.path.exists(filename):
            print(f"File {filename} doesn't exist.")
            return
        command = f"INDEX {filename} {port}"
        response = self.send_command(command)
        if response:
            print(f"Indexing response: {response}")

    def handle_search(self, filename): # send a search command to look for a file
        command = f"SEARCH {filename}"
        response = self.send_command(command)
        if response:
            print(f"Search results: {response}")

    def request_file_from_peer(self, peer_ip, peer_port, filename): # request a file directly from a peer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
                peer_sock.connect((peer_ip, peer_port))
                peer_sock.send(f"REQUEST {filename}".encode())
                with open(f"downloaded_{filename}", "wb") as f:
                    print(f"Downloading {filename} from {peer_ip}:{peer_port}...")
                    while True:
                        data = peer_sock.recv(1024)
                        if not data:
                            break
                        f.write(data)
                print(f"File {filename} downloaded successfully.")
        except Exception as e:
            print(f"Failed to request file from peer: {e}")


if __name__ == "__main__":
    client = Client()