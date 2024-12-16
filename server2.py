import socket
import threading
import json
from util import (
    hash_file,
    generate_AES_key,
    aes_encrypt_file,
    aes_decrypt_file,
    sign_data_rsa,
    verify_signature_rsa,
    store_password,
    load_stored_password,
    verify_password,
    load_database,
    save_database,
    generate_RSA_keypair,
)

SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_RSA_keypair()

database = load_database()
database_lock = threading.Lock()


def handle_client(client_socket, client_address):
    print(f"Client connected: {client_address}")
    try:
        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break

            command, *args = data.split()
            if command == "REGISTER":
                username, password = args
                if load_stored_password(username):
                    client_socket.send(b"USERNAME_TAKEN")
                else:
                    store_password(username, password)
                    client_socket.send(b"REGISTER_SUCCESS")
            elif command == "LOGIN":
                username, password = args
                if verify_password(username, password):
                    client_socket.send(b"LOGIN_SUCCESS")
                else:
                    client_socket.send(b"LOGIN_FAILURE")
            elif command == "INDEX":
                username, filename, ip, port = args
                file_hash = hash_file(filename)
                signed_index = sign_data_rsa(file_hash.encode(), SERVER_PRIVATE_KEY)

                with database_lock:
                    database["file_index"][filename] = {
                        "username": username,
                        "ip": ip,
                        "port": port,
                        "hash": file_hash,
                        "signature": signed_index.hex(),
                    }
                    save_database(database)
                client_socket.send(b"INDEX_SUCCESS")
            elif command == "SEARCH":
                query = args[0]
                with database_lock:
                    matches = [
                        {
                            "filename": filename,
                            **file_data,
                        }
                        for filename, file_data in database["file_index"].items()
                        if query in filename
                    ]
                client_socket.send(json.dumps(matches).encode())
            elif command == "VERIFY_INDEX":
                filename = args[0]
                with database_lock:
                    file_data = database["file_index"].get(filename)
                    if not file_data:
                        client_socket.send(b"FILE_NOT_FOUND")
                        continue

                is_valid = verify_signature_rsa(
                    file_data["hash"].encode(),
                    bytes.fromhex(file_data["signature"]),
                    SERVER_PUBLIC_KEY,
                )
                if is_valid:
                    client_socket.send(b"INDEX_VALID")
                else:
                    client_socket.send(b"INDEX_INVALID")
            else:
                client_socket.send(b"UNKNOWN_COMMAND")
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()

def start_server(host="0.0.0.0", port=49152):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server running on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()