import socket
import threading
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
    generate_salt
)

# Port Number 
PORT_NUMBER = 5000

# Dictionary to store files and their peers
file_index = {}

# Locks for thread safety when accessing the shared file_index
file_index_lock = threading.Lock()

# Handles communication with a single client
def handle_client(cliSock, cliInfo):
    print(f"Connection established with {cliInfo}")
    try:
        while True:
            # Receive data or message
            data = cliSock.recv(1024).decode()
            if not data:
                break

            command, *args = data.split()

            if command == "INDEX":
                # Command to index the file with peer info
                filename = args[0]
                peer_ip = cliInfo[0]
                peer_port = int(args[1])

                # Lock the file index for thread safety
                with file_index_lock:
                    if filename not in file_index:
                        file_index[filename] = []
                    file_index[filename].append((peer_ip, peer_port))

                cliSock.send(b"File indexed successfully.")

            elif command == "SEARCH":
                # Command to search for a file and return peers
                filename = args[0]
                with file_index_lock:
                    peers = file_index.get(filename, [])
                cliSock.send(str(peers).encode())

            elif command == "SEND_FILE":
                # Command to send the requested file to the client
                filename = args[0]
                if os.path.exists(filename):
                    cliSock.send(b"OK")
                    with open(filename, 'rb') as file:
                        while chunk := file.read(1024):
                            cliSock.send(chunk)
                    print(f"Sent {filename} to {cliInfo}")
                else:
                    cliSock.send(b"File not found.")

            else:
                cliSock.send(b"Invalid command.")

    except Exception as e:
        print(f"An error occurred with client {cliInfo}: {e}")
    finally:
        print(f"Closing connection with {cliInfo}")
        cliSock.close()

# Starts server and listens for incoming connections
def start_server():
    print("Server started")
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.bind(('0.0.0.0', PORT_NUMBER))
    serverSock.listen(5)  # Can handle 5 clients concurrently
    print(f"Server listening on {PORT_NUMBER}")
    
    try:
        while True:
            cliSock, cliInfo = serverSock.accept()
            client_thread = threading.Thread(target=handle_client, args=(cliSock, cliInfo))
            client_thread.start()
    
    except KeyboardInterrupt:
        print("\nServer shutting down.")    
    
    finally:
        serverSock.close()

if __name__ == "__main__":
    start_server()
