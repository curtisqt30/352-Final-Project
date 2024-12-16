class Client:
    def __init__(self, server_ip="127.0.0.1", server_port=49152):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_files_dir = "client_files"
        self.username = None  # To track logged-in user
        os.makedirs(self.local_files_dir, exist_ok=True)

    def connect_to_server(self):
        try:
            self.server_socket.connect((self.server_ip, self.server_port))
            print(f"Connected to server at {self.server_ip}:{self.server_port}")
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            exit(1)

    def register(self):
        username = input("Enter a username: ").strip()
        password = input("Enter a password: ").strip()
        self.server_socket.send(f"REGISTER {username} {password}".encode())
        response = self.server_socket.recv(1024).decode()
        if response == "REGISTER_SUCCESS":
            print("Registration successful! Please login.")
        elif response == "USERNAME_TAKEN":
            print("Username already taken. Try again.")
        else:
            print("Registration failed. Try again.")

    def login(self):
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()
        self.server_socket.send(f"LOGIN {username} {password}".encode())
        response = self.server_socket.recv(1024).decode()
        if response == "LOGIN_SUCCESS":
            print("Login successful!")
            self.username = username
            return True
        else:
            print("Invalid credentials. Please try again.")
            return False

    def ensure_login(self):
        while not self.username:
            print("\n==============================")
            print("          MAIN MENU           ")
            print("==============================")
            print("[1] 🔑 Login")
            print("[2] 📝 Register")
            print("[3] ❌ Exit")
            print("==============================")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                if self.login():
                    break
            elif choice == "2":
                self.register()
            elif choice == "3":
                self.server_socket.close()
                exit(0)
            else:
                print("Invalid choice. Try again.")

    def index_file(self):
        filename = input("Enter the filename to index: ").strip()
        file_path = os.path.join(self.local_files_dir, filename)
        if not os.path.exists(file_path):
            print(f"File '{filename}' does not exist.")
            return

        file_hash = hash_file(file_path)
        self.server_socket.send(f"INDEX {self.username} {filename} {socket.gethostbyname(socket.gethostname())} 5000".encode())
        response = self.server_socket.recv(1024).decode()
        print(response)

    def search_file(self):
        query = input("Enter filename to search: ").strip()
        self.server_socket.send(f"SEARCH {query}".encode())
        try:
            response = self.server_socket.recv(1024).decode()
            files = json.loads(response)
            if files:
                print("Files found:")
                for file in files:
                    print(file)
            else:
                print("No files found.")
        except json.JSONDecodeError:
            print("Error decoding server response.")

    def validate_file_index(self):
        filename = input("Enter the filename to validate: ").strip()
        self.server_socket.send(f"VERIFY_INDEX {filename}".encode())
        response = self.server_socket.recv(1024).decode()
        if response == "INDEX_VALID":
            print(f"The file index for '{filename}' is valid.")
        else:
            print(f"The file index for '{filename}' is invalid.")

    def main_menu(self):
        self.connect_to_server()
        self.ensure_login()
        while True:
            print("\n===================================")
            print(f"   WELCOME, {self.username.upper()}!")
            print("===================================")
            print("[1] 📤 Index File")
            print("[2] 📂 Search File")
            print("[3] 🛡️ Validate File Index")
            print("[4] 🔙 Exit")
            print("===================================")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.index_file()
            elif choice == "2":
                self.search_file()
            elif choice == "3":
                self.validate_file_index()
            elif choice == "4":
                print("Exiting client...")
                self.server_socket.close()
                break
            else:
                print("Invalid choice. Try again.")


if __name__ == "__main__":
    client = Client()
    client.main_menu()
