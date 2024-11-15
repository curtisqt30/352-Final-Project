import socket

def start_server():
    print("Server started")
    PORT_NUMBER = 5000
    
    # Socket default values, AF_NET = IPv4 and SOCK_STREAM = TCP
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to IP 0.0.0.0 and the port
    serverSock.bind(('0.0.0.0', PORT_NUMBER))
    
    # Listen for incoming connections max 2
    serverSock.listen(2);
    
    #serverSock.accept()
    
    while True:
        # Accept incoming connection
        cliSock, cliInfo = serverSock.accept()
        print("Connection established with ", cliInfo)
        
        # File sharing logic
       
        # Close socket afterwards 
        cliSock.close()

if __name__ == "__main__":
    start_server()