import socket
import threading
import json
from util import (
    aes_encrypt_file,
    generate_AES_key,
    verify_password,
    load_stored_password,
    store_password,
    load_database,
    save_database,
    get_current_timestamp,
)

# Database and locks for thread safety
database = load_database()
file_index_lock = threading.Lock()
peer_list_lock = threading.Lock()

# Debugging utility to log the database structure
def debug_database():
    print("\nCurrent Database State:")
    print(json.dumps(database, indent=4))

# Handles communication with a single client
def handle_client(cliSock, cliInfo):
    print(f"Connection established with {cliInfo}")
    peer_ip, peer_port = cliInfo
    listening_port = None

    try:
        # Handle initial LISTEN_PORT message
        data = cliSock.recv(1024).decode()
        if data.startswith("LISTEN_PORT"):
            listening_port = data.split()[1]
            print(f"Received listening port {listening_port} from {peer_ip}")
            cliSock.send(b"LISTEN_PORT_ACK")

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
                    with peer_list_lock:
                        # Remove old entries for the same username
                        for ip, peers in list(database["peers"].items()):
                            database["peers"][ip] = [
                                peer for peer in peers if peer["username"] != username
                            ]
                            if not database["peers"][ip]:
                                del database["peers"][ip]

                        # Add the new peer entry
                        if peer_ip not in database["peers"]:
                            database["peers"][peer_ip] = []
                        database["peers"][peer_ip].append({
                            "username": username,
                            "ip": peer_ip,
                            "port": peer_port,
                            "listening_port": listening_port
                        })
                        save_database(database)
                        debug_database()

                    # Send login success confirmation to client
                    print(f"User {username} logged in successfully from {peer_ip}:{peer_port}")
                    cliSock.send(b"LOGIN_SUCCESS")
                else:
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

            elif command == "REQUEST_PEER":
                print(f"REQUEST_PEER command received with args: {args}")  # Debugging log
                if len(args) < 1:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

                requested_username = args[0]
                with peer_list_lock:
                    peer_found = None
                    for ip, peers in database["peers"].items():
                        for peer in peers:
                            if isinstance(peer, dict) and peer.get("username") == requested_username:
                                peer_found = peer
                                break
                        if peer_found:
                            break

                if peer_found:
                    print(f"Peer found: {peer_found}")  # Debugging log
                    if "incoming_requests" not in database:
                        database["incoming_requests"] = {}

                    if requested_username not in database["incoming_requests"]:
                        database["incoming_requests"][requested_username] = []

                    database["incoming_requests"][requested_username].append({
                        "from": args[0],
                        "peer_info": {
                            "ip": peer_found["ip"],
                            "port": peer_found["port"],
                            "listening_port": peer_found["listening_port"]
                        }
                    })

                    save_database(database)

                    response = f"PEER_FOUND {peer_found['username']} {peer_found['ip']} {peer_found['port']}"
                    print(f"Sending response to client: {response}")  # Debugging log
                    cliSock.send(response.encode())
                else:
                    print(f"Peer '{requested_username}' not found.")  # Debugging log
                    cliSock.send(b"PEER_NOT_FOUND")

            elif command == "LIST_PEERS":
                with peer_list_lock:
                    peer_list = []
                    for ip, peers in database["peers"].items():
                        if isinstance(peers, list):
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

            elif command == "LIST_INCOMING_REQUESTS":
                username = args[0] if args else None
                if not username:
                    cliSock.send(b"INVALID_ARGUMENTS")
                    continue

                with peer_list_lock:
                    incoming_requests = database.get("incoming_requests", {}).get(username, [])

                if incoming_requests:
                    formatted_requests = [
                        f"From: {request['from']} | Peer Info: {request['peer_info']}"
                        for request in incoming_requests
                    ]
                    response = "INCOMING_REQUESTS " + "\n".join(formatted_requests)
                    cliSock.send(response.encode())
                else:
                    cliSock.send(b"INCOMING_REQUESTS_EMPTY")

    except Exception as e:
        print(f"Error with client {cliInfo}: {e}")

    finally:
        with peer_list_lock:
            # Remove the disconnected peer
            if peer_ip in database["peers"]:
                database["peers"][peer_ip] = [
                    peer for peer in database["peers"][peer_ip] if peer["port"] != peer_port
                ]
                # If no peers remain for this IP, delete the entry
                if not database["peers"][peer_ip]:
                    del database["peers"][peer_ip]

            # Remove any old sessions for the same username
            for ip, peers in list(database["peers"].items()):
                database["peers"][ip] = [
                    peer for peer in peers if peer["username"] != args[0]
                ]
                if not database["peers"][ip]:
                    del database["peers"][ip]

            save_database(database)
            debug_database()
        print(f"Connection closed with {cliInfo}")
        cliSock.close()

# Starts server and listens for incoming connections
def start_server(host, port):
    print("Server started")
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.bind((host, port))
    serverSock.listen(5)  # Can handle 5 clients concurrently
    print(f"Server listening on {host}:{port}")

    try:
        while True:
            cliSock, cliInfo = serverSock.accept()
            threading.Thread(target=handle_client, args=(cliSock, cliInfo), daemon=True).start()

    except KeyboardInterrupt:
        print("\nServer shutting down.")

    finally:
        serverSock.close()

if __name__ == "__main__":
    start_server("127.0.0.1", 49152)
