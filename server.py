import socket
import threading
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
    load_key,
    load_database,
    save_database
)

# Port Number 
PORT_NUMBER = 55555

# Dictionary to store files and their peers
file_index = {}

# Dictionary to store peer list
peers = {}

# Locks for thread safety when accessing shared resources
file_index_lock = threading.Lock()
peer_list_lock = threading.Lock()

# Handles communication with a single client
def handle_client(cliSock, cliInfo):
    print(f"Connection established with {cliInfo}")
    peer_ip, peer_port = cliInfo

    try:
        # Load current database
        database = load_database()

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
                filename = args[0]
                with file_index_lock:
                    database = load_database()
                    if filename not in database["file_index"]:
                        database["file_index"][filename] = []
                    database["file_index"][filename].append((peer_ip, peer_port))
                    save_database(database)
                cliSock.send(b"File indexed successfully.")

            elif command == "REQUEST_FILE_LIST":
                with file_index_lock:
                    database = load_database()
                    file_list = str(list(database["file_index"].keys()))
                cliSock.send(file_list.encode())


            elif command == "LIST_PEERS":
                with peer_list_lock:
                    database = load_database()
                    peer_list = str(database["peers"])
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
            database = load_database()
            if peer_ip in database["peers"]:
                del database["peers"][peer_ip]
                save_database(database)
        print(f"Connection closed with {cliInfo}")
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
