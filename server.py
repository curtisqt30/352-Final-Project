import socket
import os
import threading
import pwinput
from tqdm import tqdm
import json

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
    load_key,
    load_database,
    save_database
)

# dictionary to store client information
client_sessions = {}

# Database loaded once at the start
database = load_database()

# Generate RSA keys for the server
private_key, public_key = generate_RSA_keypair()
print("\nServer RSA Private Key:")
print(private_key.decode())
print("\nServer RSA Public Key:")
print(public_key.decode())

# Locks for thread safety
file_index_lock = threading.Lock()
peer_list_lock = threading.Lock()

def save_sessions_to_file():
    with open('sessions.txt', 'w') as f:
        for client_socket, session in client_sessions.items():
            username, ip, port = session
            f.write(f"{username},{ip}:{port}\n")
            
def load_sessions_from_file():
    try:
        with open('sessions.txt', 'r') as f:
            for line in f.readlines():
                username, session_info = line.strip().split(',')
                ip, port = session_info.split(':')
                client_sessions[username] = (username, ip, int(port))
    except FileNotFoundError:
        print("No saved sessions found.")


# Handles communication with a single client
def handle_client(cliSock, cliInfo):
    print(f"Connection established with {cliInfo}")
    peer_ip, peer_port = cliInfo
    
    #
    
    try:
        # Register the peer in the peer list
        with peer_list_lock:
            database["peers"][peer_ip] = peer_port
            save_database(database)

        while True:
            data = cliSock.recv(1024).decode()
            if not data:
                break

            command, *args = data.split()

            if command == "LOGIN":
                username, password = args
                if verify_password(username, password):
                    # Log the successful login
                    with open("login_logs.txt", "a") as log_file:
                        log_file.write(f"User {username} logged in from {peer_ip}:{peer_port}\n")
                    print(f"User {username} logged in from {peer_ip}:{peer_port}")
                    
                    cliSock.send(b"LOGIN_SUCCESS")
                else:
                    cliSock.send(b"LOGIN_FAILURE")

            elif command == "REGISTER":
                username, password = args
                if load_stored_password(username):
                    cliSock.send(b"USERNAME_TAKEN")
                else:
                    store_password(username, password)
                    cliSock.send(b"REGISTER_SUCCESS")

            elif command == "INDEX":
                filename, username, port = args
                if not os.path.exists(filename):
                    cliSock.send(f"File {filename} not found.".encode())
                    continue

                # Add the file to the index database with the username, IP, and port
                with file_index_lock:
                    if filename not in database["file_index"]:
                        database["file_index"][filename] = []
                    # Store the file
                    database["file_index"][filename].append({
                        "username": username,
                        "ip": peer_ip,
                        "port": port
                    })
                    save_database(database)

                cliSock.send(b"File indexed successfully.")

            elif command == "LIST_FILES":
                with file_index_lock:
                    file_list = [
                        {"filename": filename, "peers": database["file_index"][filename]}
                        for filename in database["file_index"]
                    ]
                response = json.dumps(file_list) 
                cliSock.send(response.encode())

            elif command == "LIST_PEERS":
                with peer_list_lock:
                    peer_list = ",".join([f"{ip}:{port}" for ip, port in database["peers"]]) 
                cliSock.send(peer_list.encode()) 

            elif command == "SEND_FILE":
                filename = args[0]
                encrypted_file = aes_encrypt_file(filename, generate_AES_key())
                with open(encrypted_file, 'rb') as file:
                    while chunk := file.read(1024):
                        cliSock.send(chunk)
                os.remove(encrypted_file)

            else:
                cliSock.send(b"Invalid command.")

    except Exception as e:
        print(f"Error with client {cliInfo}: {e}")

    finally:
        with peer_list_lock:
            if peer_ip in database["peers"]:
                del database["peers"][peer_ip]
                save_database(database)
        print(f"Connection closed with {cliInfo}")
        cliSock.close()

# Starts server and listens for incoming connections
def start_server(host, port):
    print("Server started")
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.bind((host, port))
    serverSock.listen(5)  # Can handle 5 clients concurrently
    print(f"Server listening on {host}:{port}...")
    
    load_sessions_from_file()
    
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
    start_server("127.0.0.1", 55555)
