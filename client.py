import socket
import os
# from Crypto.Cipher import AES
# from Crypto.Hash import SHA256


def client_decrypt_file():
    pass
    # key = b'sixteen byte key'
    # cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    # plaintext = cipher.decrypt(ciphertext)
    # try:
    #   cipher.verify(tag)
    #   printf("Message is verified: ", plaintext)
    # except ValueError:
    #   print("key is incorrect or message is corrupted")

def client_encrypt_file():
    pass
    # key = b'sixteen byte key'
    # cipher = AES.new(key, AES.MODE_EAX)
    #
    # nonce = cipher.nonce
    # cipher, tag = cipher.encrypt_and_digest(data)
    
def client_hash_file():
    pass
    
def client_public_key():

def start_client():
    cliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    PORT_NUMBER = 5000
    SERVER_IP = '0.0.0.0'  # Replace with the actual server IP if remote
    
    try:
        # Connect to the server
        cliSock.connect((SERVER_IP, PORT_NUMBER))
        print(f"Connected to server {SERVER_IP} on port {PORT_NUMBER}")
        
        while True:
            # Get user input to send a command
            command = input("Enter a command (INDEX <filename> <port> or SEARCH <filename> or EXIT): ").strip()
            
            if command.lower() == "exit":
                print("Closing client connection.")
                break

            elif command.startswith("INDEX"):
                cliSock.send(command.encode())
                response = cliSock.recv(1024).decode()
                print(f"Server response: {response}")
            
            elif command.startswith("SEARCH"):
                cliSock.send(command.encode())
                response = cliSock.recv(1024).decode()
                print(f"Server response: {response}")
                
                # Assume we get a list of peers and pick the first one
                peers = eval(response)
                if peers:
                    peer_ip, peer_port = peers[0]
                    print(f"Connecting to peer {peer_ip}:{peer_port} to request the file.")
                    
                    # Request the file from the peer
                    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer_sock.connect((peer_ip, peer_port))
                    peer_sock.send(f"SEND_FILE {command.split()[1]}".encode())
                    
                    # Receive the file
                    file_data = peer_sock.recv(1024)
                    if file_data == b"OK":
                        with open("received_file.txt", "wb") as file:
                            while True:
                                chunk = peer_sock.recv(1024)
                                if not chunk:
                                    break
                                file.write(chunk)
                        print("File received successfully.")
                    else:
                        print("Failed to retrieve the file.")
                    peer_sock.close()
                
                else:
                    print("No peers found for the file.")
            
            else:
                print("Invalid command.")
    
    except Exception as e:
        print(f"An error occurred: {e}")
    
    finally:
        cliSock.close()
        print("Client disconnected.")

if __name__ == "__main__":
    start_client()
