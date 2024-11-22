import socket
import os
from encryption_util import (
    aes_encrypt_file,
    aes_decrypt_file,
    hash_file,
    generate_AES,
    generate_RSA,
    generate_DSA,
    sign_data_rsa,
    verify_signature_rsa,
    sign_data_dsa,
    verify_signature_dsa,
    rsa_encrypt,
    rsa_decrypt,
    hash_password,
    verify_password,
    generate_salt,
)

class Client:
    def __init__(self, server_ip="0.0.0.0", port_number=5000):
        self.server_ip = server_ip
        self.port_number = port_number
        self.cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
        pass

    def disconnect(self):
        pass

    def send_command(self, command):
        pass

    def handle_index(self, filename, port):
        pass

    def handle_search(self, filename):
        pass

    def request_file_from_peer(self, peer_ip, peer_port, filename):
        pass


if __name__ == "__main__":
    client = Client()