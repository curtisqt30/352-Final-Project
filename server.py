import socket
import threading

PORT_NUMBER = 5000

# Handles communication with a single client
def handle_client(cliSock, cliInfo):
    print(f"Connection established with {cliInfo}")

    try
        while True:
            # receive data or message
            data = cliSock.recv(1024)
            if not data:
                break
            print(f"Received from {cliInfo}: {data.decode()}")
            # add more logic here?

    except Exception as e:
        print(f"An error occured with client {cliInfo}: {e}")
    finally:
        print(f"Closing connection with {cliInfo}")
        cliSock.close()

# Starts server and listens for incoming connections
def start_server():
    print("Server started")
    
    # Socket default values, AF_NET = IPv4 and SOCK_STREAM = TCP
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to IP 0.0.0.0 and the port
    serverSock.bind(('0.0.0.0', PORT_NUMBER))
    
    # Listen for incoming connections max 2
    serverSock.listen(2)
    print(f"Server listening on {PORT_NUMBER}")
    
    try:
        while True:
            # Accept incoming connection
            cliSock, cliInfo = serverSock.accept()
            # Create a new thread to handle client
            client_thread = threading.thread(target=handle_client, args=(cliSock, cliInfo))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")    
    
    finally:
        # Close socket afterwards 
        serverSock.close()

if __name__ == "__main__":
    start_server()
