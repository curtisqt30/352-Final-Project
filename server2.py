import socket
import threading
import json
import ssl
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import NoEncryption
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
    generate_RSA_keypair,
)

# Generate RSA keys for signing
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_RSA_keypair()

# Load database and create lock
database = load_database()
database_lock = threading.Lock()

# The function to handle client requests
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

# Fnuction to generate or replace the old self-signed certificate
def generate_self_signed_cert(cert_file="server_cert.pem", key_file="server_key.pem"):
    if os.path.exists(cert_file) or os.path.exists(key_file):
        choice = input("Old certificate and key found. Do you want to replace them? (yes/no): ").strip().lower()
        if choice == "yes":
            print("Replacing old certificate and key...")
            os.remove(cert_file) if os.path.exists(cert_file) else None
            os.remove(key_file) if os.path.exists(key_file) else None
        else:
            print("Using existing certificate and key.")
            return

    print("Generating new self-signed certificate...")

    # Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Build certificate subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])

    # Define SAN for IP and localhost
    san = x509.SubjectAlternativeName([
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),  # Convert string to IPv4Address
        x509.DNSName("localhost")
    ])

    # Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # Valid for 1 year
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Write private key to file
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write certificate to file
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("New self-signed certificate and key generated.")
    
# The Function to start the server
def start_server(host="127.0.0.1", port=49152):
    try:
        # Configure SSL/TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")  # Certificate and key

        # Create and wrap server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(server_socket, server_side=True)

        secure_socket.bind((host, port))
        secure_socket.listen(5)
        print(f"Secure server running on {host}:{port}")

        # Accept and handle clients
        while True:
            client_socket, client_address = secure_socket.accept()
            print(f"New secure connection from {client_address}")
            threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()

    except FileNotFoundError:
        print("Error: Certificate or key file not found. Ensure 'server_cert.pem' and 'server_key.pem' are available.")
    except ssl.SSLError as ssl_error:
        print(f"SSL error occurred: {ssl_error}")
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        if 'secure_socket' in locals():
            secure_socket.close()

if __name__ == "__main__":
    generate_self_signed_cert()
    start_server()