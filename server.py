import sockets

def start_server():
    
    PORT_NUMBER = 5000
    
    # Socket default values, AF_NET = IPv4 and SOCK_STREAM = TCP
    serverSock = socket.socket(socket.AF_NET, socket.SOCK_STREAM)
    serverSock.bind(('0.0.0.0', PORT_NUMBER))
    
    serverSock.listen(5);
    
    #serverSock.accept()
    
    while True:
        cliSock, cliInfo = serverSock.accept()
        
        cliSock.close()

