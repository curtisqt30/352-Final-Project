import socket
import threading
import os

# TODO: Define global file index (mapping keywords to lists of peer info)
# Example: file_index = {'keyword1': [('peer1.com', 12345), ('peer2.com', 12346)], 'keyword2': [('peer3.com', 12347)]}
file_index = {}

# TODO: Function to handle client login, receive credentials, and authenticate
def handle_login(client_socket):
    # TODO: Receive the ID and password from the client (client will send these)

    # TODO: Authenticate user (This could be a simple check or check against a database)
    # For simplicity, let's assume a basic check:
    
    pass

# TODO: Function to handle file indexing (this stores information about files that each peer has)
def handle_file_indexing(client_socket):
    # TODO: Receive file data (e.g., file names and keywords)
     # Expecting something like "file1, keyword1"
    
    # TODO: Parse the data and update the global file_index (store in the format {'keyword': [('peer', port)]})
    
    pass

# TODO: Function to handle file search requests from clients
def handle_file_search(client_socket):
    # TODO: Receive search request (e.g., keyword from client)

    # TODO: Search for the keyword in the file_index and send results
    
    # Return list of peers with the keyword
    pass


# TODO: Function to initiate a file transfer (optional for now, as it's handled peer-to-peer)
def handle_file_transfer(client_socket):
    # TODO: Receive request for file transfer (e.g., peer info) from the client
    
    # TODO: Send back confirmation of the file transfer initiation
    pass

# TODO: Main function to handle all client communications
def handle_client(client_socket):
        # 1. Handle login

        # 2. Handle file indexing (after login)

        # 3. Handle file search requests (client will send a keyword to search for)

        # 4. Handle file transfer request (client will request file transfer)
    pass

# TODO: Function to start the server and accept client connections
def start_server(host, port):
    # 1. Create server socket and bind it to the provided host and port

    # 2. Start listening for incoming connections (max 5 concurrent connections)

        # 3. Accept client connections and create a new thread for each client

        
        # 4. Start a new thread to handle the client (to allow concurrent requests)

# TODO: Run the server on localhost:12345 (for testing)
    pass