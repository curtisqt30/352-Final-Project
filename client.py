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
        self.cli_sock.send(command.encode())
        response = self.cli_sock.recv(1024).decode()
        print(f"Server response: {response}")

    def handle_index(self, filename, port):
        pass

    def handle_search(self, filename):
        pass

    def request_file_from_peer(self, peer_ip, peer_port, filename):
        pass


if __name__ == "__main__":
    client = Client()