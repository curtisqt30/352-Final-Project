import socket
import os
import threading
import pwinput
from tqdm import tqdm
import json

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

# dictionary to store client information
client_sessions = {}

# Database loaded once at the start
database = load_database()

'''
# Generate RSA keys for the server
private_key, public_key = generate_RSA_keypair()
print("\nServer RSA Private Key:")
print(private_key.decode())
print("\nServer RSA Public Key:")
print(public_key.decode())
'''

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
    
    try:
        listening_port = None
        
        data = cliSock.recv(1024).decode()  # receive the listen port information
        if data.startswith("LISTEN_PORT"):
            listening_port = data.split()[1]
            print(f"Received listen port: {listening_port} from {peer_ip}")
            cliSock.send(b"LISTEN_PORT_ACK")  # Acknowledge
        
        while True:
            data = cliSock.recv(1024).decode()
            if not data:
                break

            command, *args = data.split()

            if command == "LOGIN":
                if len(args) < 2:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

                username, password = args
                if verify_password(username, password):
                    # Pass: log the login attempt
                    with open("login_logs.txt", "a") as log_file:
                        log_file.write(f"{get_current_timestamp()} | User {username} logged in successfully from {peer_ip}:{peer_port}\n")
                    print(f"User {username} logged in successfully from {peer_ip}:{peer_port}")
                    
                    cliSock.send(b"LOGIN_SUCCESS")

                    # Register the peer with the correct username
                    with peer_list_lock:
                        # Ensure that the peer list for the IP is always a list
                        if peer_ip not in database["peers"]:
                            database["peers"][peer_ip] = []

                        # Append the peer information
                        database["peers"][peer_ip].append({
                            "username": username,
                            "ip": peer_ip,
                            "port": peer_port,
                            "listening_port": listening_port
                        })
                        save_database(database)

                else:
                    # Fail: Log the login attempt
                    with open("login_logs.txt", "a") as log_file:
                        log_file.write(f"{get_current_timestamp()} | Failed login attempt for user {username} from {peer_ip}:{peer_port}\n")
                    print(f"Failed login attempt for user {username} from {peer_ip}:{peer_port}")
                    
                    cliSock.send(b"LOGIN_FAILURE")

            elif command == "REGISTER":
                if len(args) < 2:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue
                
                username, password = args
                if load_stored_password(username):
                    cliSock.send(b"USERNAME_TAKEN")
                else:
                    store_password(username, password)
                    cliSock.send(b"REGISTER_SUCCESS")

            elif command == "INDEX":
                if len(args) < 2:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

                filename, username, port = args
                if not os.path.exists(filename):
                    cliSock.send(f"File {filename} not found.".encode())
                    continue

                # Add the file to the index database with the username, IP, and port
                with file_index_lock:
                    if filename not in database["file_index"]:
                        database["file_index"][filename] = []
                    database["file_index"][filename].append({
                        "username": username,
                        "ip": peer_ip,
                        "port": port
                    })
                    save_database(database)

                cliSock.send(b"File indexed successfully.")

            elif command == "LIST_FILES": # List files
                with file_index_lock:
                    file_list = [
                        {"filename": filename, "peers": database["file_index"][filename]}
                        for filename in database["file_index"]
                    ]
                response = json.dumps(file_list) 
                cliSock.send(response.encode())

            elif command == "LIST_PEERS": # List peers
                with peer_list_lock:
                    peer_list = []
                    for ip, peers in database["peers"].items():
                        for peer in peers:
                            peer_info = (
                                f"Username: {peer['username']}, "
                                f"IP: {peer['ip']}, "
                                f"Port: {peer['port']}, "
                                f"Listening Port: {peer['listening_port']}"
                            )
                            peer_list.append(peer_info)
                    response = "\n".join(peer_list)
                cliSock.send(response.encode())

            elif command == "REQUEST_PEER":
                if len(args) < 1:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

                requested_username = args[0]
                with peer_list_lock:
                    peer_found = None
                    for ip, peers in database["peers"].items():
                        for peer in peers:
                            if peer['username'] == requested_username:
                                peer_found = peer
                                break
                        if peer_found:
                            break

                if peer_found:
                    with peer_list_lock:
                        if "incoming_requests" not in database:
                            database["incoming_requests"] = []
                        database["incoming_requests"].append({
                            "from": requested_username,
                            "to": peer_found['username'],
                            "peer": peer_found,
                        })
                    response = f"PEER_FOUND {peer_found['username']} {peer_found['ip']} {peer_found['port']}"
                    cliSock.send(response.encode())
                else:
                    cliSock.send(b"PEER_NOT_FOUND")
            
            elif command == "CLEAR_INCOMING_REQUESTS":
                with peer_list_lock:
                    database["incoming_requests"] = []
                cliSock.send("INCOMING_REQUESTS_CLEARED".encode())

            elif command == "LIST_INCOMING_REQUESTS":
                with peer_list_lock:
                    incoming_requests = database.get("incoming_requests", [])

                if incoming_requests:
                    formatted_requests = []
                    for request in incoming_requests:
                        formatted_requests.append(
                            f"From: {request['from']} to: {request['to']} - Peer Info: {request['peer']}"
                        )
                    response = "INCOMING_REQUESTS " + "\n".join(formatted_requests)
                    cliSock.send(response.encode())
                else:
                    response = "INCOMING_REQUESTS_EMPTY"
                    cliSock.send(response.encode())

            elif command == "ACCEPT_REQUEST":
                if len(args) < 1:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

                filename = args[0]
                with file_index_lock:
                    requests = database.get("file_requests", {})
                    if filename in requests:
                        del requests[filename]
                        database["file_requests"] = requests
                        save_database(database)
                        cliSock.send(b"REQUEST_ACCEPTED")
                    else:
                        cliSock.send(b"REQUEST_NOT_FOUND")

            elif command == "SEND_FILE":
                if len(args) < 1:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

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
            # Ensure that the peer list for the IP is a list before modifying it
            if peer_ip in database["peers"]:
                # Remove the specific peer with the matching username
                database["peers"][peer_ip] = [
                    peer for peer in database["peers"][peer_ip] if peer["username"] != username
                ]
                # If no more peers exist for that IP, remove the IP entry
                if not database["peers"][peer_ip]:
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
    print(f"Server listening on {host}:{port}")
    
    database = load_database()
    
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
    start_server("127.0.0.1", 49152)
