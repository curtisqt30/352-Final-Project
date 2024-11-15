import socket

def start_client():
    # Create socket object
    cliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    PORT_NUMBER = 5000
    
    # Connect to the server using its IP address and port
    cliSock.connect(('0.0.0.0', PORT_NUMBER))
    
    print("Connected to server 0.0.0.0 on port", PORT_NUMBER)
    
    # Send or receive data
    
    # Close the client socket
    cliSock.close()
    
if __name__ == "__main__":
    start_client()
