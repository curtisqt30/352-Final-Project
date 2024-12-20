import socket
import threading
import json
import ssl
import traceback
import os
import logging
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import datetime
import ipaddress
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
)

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global variables for keys
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None

# Load database
database = load_database()
database_lock = threading.Lock()

# Store Requests
pending_requests = {}  # {"username": [{"filename": ..., "requester": ..., "ip": ..., "port": ...}]}
pending_requests_lock = threading.Lock()

# Track active peers
active_peers = {}
active_peers_lock = threading.Lock()

# Data structure for tracking login attempts
login_attempts = {}
login_attempts_lock = threading.Lock()

# The function to handle client requests
def handle_client(client_socket, client_address):
    logging.info(f"Client connected: {client_address}")
    global active_peers
    username = None
    try:
        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break

            command, *args = data.split()
            if command == "REGISTER":
                if len(args) != 2:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username, password = args
                if load_stored_password(username):
                    client_socket.send(b"USERNAME_TAKEN")
                else:
                    store_password(username, password)
                    client_socket.send(b"REGISTER_SUCCESS")

            elif command == "LOGIN":
                if len(args) != 2:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username, password = args

                if verify_password(username, password):
                    client_socket.send(b"LOGIN_SUCCESS")
                    with active_peers_lock:
                        active_peers[username] = {
                            "address": client_address[0],
                            "files": [],
                        }
                    logging.info(f"User '{username}' logged in successfully.")
                    with login_attempts_lock:
                        login_attempts.pop(client_address[0], None)
                else:
                    client_socket.send(b"LOGIN_FAILURE")
                    logging.warning(f"Failed login attempt for user '{username}' from {client_address[0]}")
                    with login_attempts_lock:
                        login_attempts[client_address[0]] = login_attempts.get(client_address[0], 0) + 1

            elif command == "LOGOUT":
                if len(args) != 1:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username = args[0]
                with database_lock:
                    # Remove all files indexed by this user
                    database["file_index"] = {
                        filename: metadata
                        for filename, metadata in database["file_index"].items()
                        if metadata["username"] != username
                    }
                    save_database(database)
                with active_peers_lock:
                    if username in active_peers:
                        del active_peers[username]
                logging.info(f"Active peers after logout: {active_peers}")
                client_socket.send(b"LOGOUT_SUCCESS")
                logging.info(f"User '{username}' logged out.")

            elif command == "INDEX":
                if len(args) != 5:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username, filename, ip, port, file_hash = args
                logging.info(f"INDEX command received for file: {filename}")
                try:
                    # Sign the file hash
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
                    with active_peers_lock:
                        if username in active_peers:
                            active_peers[username]["files"].append(filename)
                    client_socket.send(b"INDEX_SUCCESS")
                except Exception as e:
                    logging.error(f"Error handling INDEX command: {e}")
                    traceback.print_exc()
                    client_socket.send(b"INDEX_FAILURE")

            elif command == "LIST_PEERS":
                with active_peers_lock:
                    response = json.dumps(active_peers)
                logging.info(f"Sending active peers list: {response}")
                client_socket.send(response.encode())

            elif command == "FILE_REQUEST":
                if len(args) != 3:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                requester, filename, peer_ip = args

                with database_lock:
                    file_info = database["file_index"].get(filename, None)

                if file_info:
                    # Add the request to the queue
                    request_queue.append({
                        "requester": requester,
                        "filename": filename,
                        "peer_ip": peer_ip,
                        "peer_port": file_info["port"],
                    })
                    client_socket.send(b"REQUEST_QUEUED")
                    logging.info(f"File request for '{filename}' queued.")
                else:
                    client_socket.send(b"FILE_NOT_FOUND")
                    logging.warning(f"File '{filename}' not found for request.")

            elif command == "REQUEST_QUEUE":
                try:
                    # Retrieve the pending requests for this user
                    pending_requests = [] 
                    response = json.dumps(pending_requests)
                    client_socket.send(response.encode())
                    logging.info(f"Pending requests sent to {username}: {response}")
                except Exception as e:
                    logging.error(f"Error handling REQUEST_QUEUE for {username}: {e}")
                    client_socket.send(b"[]")  # Send an empty list if there's an error

            elif command == "SEARCH":
                if len(args) != 1:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                query = args[0]
                with database_lock:
                    matches = [
                        {
                            "filename": filename,
                            "username": file_data["username"],
                            "ip": file_data["ip"],
                            "port": file_data["port"],
                            "hash": file_data["hash"],
                            "signature": file_data["signature"],
                        }
                        for filename, file_data in database["file_index"].items()
                        if query in filename
                    ]
                response = json.dumps(matches)
                client_socket.send(response.encode())

            else:
                client_socket.send(b"UNKNOWN_COMMAND")

    except Exception as e:
        logging.error(f"Error handling client {client_address}: {e}")
        traceback.print_exc()
    finally:
        client_socket.close()
        logging.info(f"Connection closed: {client_address}")


# Function to generate and load RSA keys
def generate_and_load_keys(key_file="server_key.pem", cert_file="server_cert.pem"):
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY

    if not os.path.exists(key_file) or not os.path.exists(cert_file):
        logging.info("Generating new self-signed certificate and key...")
        key = RSA.generate(2048)
        SERVER_PRIVATE_KEY = key
        SERVER_PUBLIC_KEY = key.publickey()

        # Save private key
        with open(key_file, "wb") as f:
            f.write(key.export_key())

        logging.info("Private key saved.")

        # Create a placeholder certificate
        cert = x509.CertificateBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
                ]
            )
        ).issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
                ]
            )
        ).public_key(
            key.publickey()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).sign(key, hashes.SHA256(), default_backend())

        # Save certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logging.info("Certificate saved.")
    else:
        # Load private key
        with open(key_file, "rb") as f:
            SERVER_PRIVATE_KEY = RSA.import_key(f.read())

        # Load public key (assume it's derived from the private key)
        SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()

        logging.info("Keys loaded successfully.")


def start_server(host="127.0.0.1", port=49152):
    try:
        generate_and_load_keys()

        # Configure SSL/TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

        # Create and wrap server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(server_socket, server_side=True)

        secure_socket.bind((host, port))
        secure_socket.listen(5)
        logging.info(f"Secure server running on {host}:{port}")

        # Accept and handle clients
        while True:
            client_socket, client_address = secure_socket.accept()
            logging.info(f"New secure connection from {client_address}")
            threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()

    except FileNotFoundError:
        logging.error("Certificate or key file not found. Ensure 'server_cert.pem' and 'server_key.pem' are available.")
    except ssl.SSLError as ssl_error:
        logging.error(f"SSL error occurred: {ssl_error}")
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        with database_lock:
            database["file_index"] = {} 
            save_database(database)
        with active_peers_lock:
            active_peers.clear()
        logging.info("File index and active peers cleared.")
    finally:
        if "secure_socket" in locals():
            secure_socket.close()

if __name__ == "__main__":
    start_server()
