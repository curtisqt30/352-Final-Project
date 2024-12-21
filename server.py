import socket
import threading
import json
import ssl
import traceback
import os
import base64
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

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global variables for keys
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None

# Load database
database = load_database()
database_lock = threading.Lock()

# Store Requests
pending_requests = {} 
pending_requests_lock = threading.Lock()

# request queue
request_queue = []
request_queue_lock = threading.Lock()

# Track active peers
active_peers = {}
active_peers_lock = threading.Lock()
peer_sockets = {}
peer_sockets_lock = threading.Lock()

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
                try:
                    username, password, client_data = args[0], args[1], json.loads(args[2])
                    algorithm = client_data["algorithm"]
                    public_key = client_data["public_key"]

                    if username in database["users"]:
                        client_socket.send(b"USERNAME_TAKEN")
                    else:
                        store_password(username, password)
                        database["users"][username] = {
                            "algorithm": algorithm,
                            "public_key": public_key
                        }
                        save_database(database)
                        client_socket.send(b"REGISTER_SUCCESS")
                except Exception as e:
                        client_socket.send(b"REGISTER_FAILURE")

            elif command == "LOGIN":
                if len(args) != 2:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username, password = args

                if verify_password(username, password):
                    with active_peers_lock:
                        active_peers[username] = {
                            "address": client_address[0],
                            "files": [],
                        }
                    with peer_sockets_lock:  # Use the lock here
                        peer_sockets[username] = client_socket
                    client_socket.send(b"LOGIN_SUCCESS")
                    logging.info(f"User '{username}' logged in successfully.")
                else:
                    client_socket.send(b"LOGIN_FAILURE")

            elif command == "LOGOUT":
                if len(args) != 1:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username = args[0]

                with active_peers_lock:
                    if username in active_peers:
                        del active_peers[username]
                with peer_sockets_lock:
                    if username in peer_sockets:
                        del peer_sockets[username]

                logging.info(f"User '{username}' logged out.")
                client_socket.send(b"LOGOUT_SUCCESS")
                
            elif command == "UPDATE_PORT":
                if len(args) != 2:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                username, peer_port = args
                with active_peers_lock:
                    if username in active_peers:
                        active_peers[username]["port"] = peer_port
                        client_socket.send(b"PORT_UPDATED")
                        logging.info(f"Updated port for {username}: {peer_port}")
                    else:
                        client_socket.send(b"USER_NOT_FOUND")

            elif command == "INDEX":
                try:
                    data = json.loads(args[0])
                    username, filename, file_hash, aes_key, signature = (
                        data["username"], data["filename"], data["file_hash"],
                        base64.b64decode(data["aes_key"]),
                        base64.b64decode(data["signature"])
                    )

                    user_info = database["users"].get(username)
                    if not user_info:
                        client_socket.send(b"USER_NOT_FOUND")
                        return

                    public_key = user_info["public_key"]
                    algorithm = user_info["algorithm"]

                    if algorithm == "RSA":
                        verified = verify_signature_rsa(file_hash.encode(), signature, public_key)
                    elif algorithm == "DSA":
                        verified = verify_signature_dsa(file_hash.encode(), signature, public_key)
                    else:
                        verified = False

                    if verified:
                        database["file_index"][filename] = {
                            "username": username,
                            "file_hash": file_hash,
                            "aes_key": base64.b64encode(aes_key).decode(),
                            "signature": signature.hex()
                        }
                        save_database(database)
                        client_socket.send(b"INDEX_SUCCESS")
                    else:
                        client_socket.send(b"SIGNATURE_INVALID")
                except Exception as e:
                    client_socket.send(b"INDEX_FAILURE")

            elif command == "LIST_PEERS":
                with active_peers_lock:
                    response = json.dumps(active_peers)
                logging.info(f"Sending active peers list: {response}")
                client_socket.send(response.encode())

            elif command == "FILE_REQUEST":
                if len(args) != 3:  # Ensure the correct number of arguments
                    logging.warning(f"Invalid FILE_REQUEST args: {args}")
                    client_socket.send(b"INVALID_ARGS")
                    continue

                requester, filename, peer_ip = args  # Extract arguments

                logging.info(f"Received FILE_REQUEST from {requester} for {filename}")

                with database_lock:
                    file_info = database["file_index"].get(filename, None)

                if file_info:
                    owner = file_info["username"]  # The owner of the file

                    with active_peers_lock:
                        if owner in active_peers:
                            owner_port = active_peers[owner]["port"]  # Use the dynamically updated port

                            with pending_requests_lock:
                                if owner not in pending_requests:
                                    pending_requests[owner] = []  # Initialize if not already present
                                pending_requests[owner].append({
                                    "requester": requester,
                                    "filename": filename,
                                    "peer_ip": peer_ip,
                                    "peer_port": owner_port,  # Use the correct port
                                })

                            client_socket.send(b"REQUEST_QUEUED")
                            logging.info(f"File request for '{filename}' queued.")
                        else:
                            client_socket.send(b"OWNER_NOT_FOUND")
                else:
                    client_socket.send(b"FILE_NOT_FOUND")

            elif command == "REQUEST_QUEUE":
                try:
                    # Retrieve the pending requests for this user
                    with pending_requests_lock:
                        user_requests = pending_requests.get(username, [])
                    response = json.dumps(user_requests)
                    client_socket.send(response.encode())
                    logging.info(f"Pending requests sent to {username}: {response}")
                except Exception as e:
                    logging.error(f"Error handling REQUEST_QUEUE for {username}: {e}")
                    client_socket.send(b"[]")  # Send an empty list if there's an error

            elif command == "REQUEST":
                file_path = os.path.join(self.local_files_dir, filename)
                if not os.path.exists(file_path):
                    logging.warning(f"Requested file '{filename}' not found.")
                    client_socket.send(b"FILE_NOT_FOUND")
                    return

                logging.info(f"Preparing to serve file '{filename}'.")
                client_socket.send(b"READY")  # Ensure only 'READY' is sent without additional data

                with open(file_path, "rb") as file:
                    while chunk := file.read(4096):
                        client_socket.send(chunk)
                        logging.debug(f"Sent chunk of size {len(chunk)} for '{filename}'.")
                logging.info(f"File '{filename}' sent successfully.")

            elif command == "APPROVE_REQUEST":
                if len(args) != 2:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                filename, requester = args

                with pending_requests_lock:
                    user_requests = pending_requests.get(username, [])
                    request = next((req for req in user_requests if req["filename"] == filename and req["requester"] == requester), None)

                    if request:
                        with peer_sockets_lock:
                            if requester in peer_sockets:
                                try:
                                    requester_socket = peer_sockets[requester]
                                    requester_socket.send(f"READY {filename}".encode())  # Notify requester
                                    logging.info(f"READY signal sent for '{filename}' to '{requester}'.")
                                except Exception as e:
                                    logging.error(f"Failed to notify requester '{requester}': {e}")
                                    client_socket.send(b"NOTIFY_FAILURE")
                                    return
                        # Remove the processed request
                        pending_requests[username] = [req for req in user_requests if req != request]
                        client_socket.send(b"REQUEST_APPROVED")
                    else:
                        client_socket.send(b"REQUEST_NOT_FOUND")

            elif command == "DENY_REQUEST":
                if len(args) != 2:
                    client_socket.send(b"INVALID_ARGS")
                    continue
                filename, requester = args

                with pending_requests_lock:
                    user_requests = pending_requests.get(username, [])
                    request = next((req for req in user_requests if req["filename"] == filename and req["requester"] == requester), None)

                    if request:
                        with peer_sockets_lock:
                            if requester in peer_sockets:
                                requester_socket = peer_sockets[requester]
                                requester_socket.send(b"DENIED")
                        # Remove the denied request
                        pending_requests[username] = [req for req in user_requests if req != request]
                        client_socket.send(b"REQUEST_DENIED")
                    else:
                        client_socket.send(b"REQUEST_NOT_FOUND")
                        
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