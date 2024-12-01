# Cryptographic Algorithms
from Crypto.PublicKey import RSA, DSA  # For RSA and DSA key pair generation
from Crypto.Signature import pkcs1_15, DSS  # for RSA and DSA signature
from Crypto.Cipher import PKCS1_OAEP, AES  # For RSA and AES encryption
from Crypto.Hash import SHA256  # for hashing data (SHA-256)
from Crypto.Random import get_random_bytes  # For random bytes
from Crypto.Util.Padding import pad, unpad
import bcrypt # For password and salting

# Standard Libraries
import os  # for file operations
import hashlib  # for hashing
import json
import threading

# AES Functions using Cipher blcok chaining mode
def aes_encrypt_file(file_path, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # read file and encrypt
    with open(file_path, 'rb') as file:
        plaintext = file.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    # save file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(iv)
        enc_file.write(ciphertext)
    return encrypted_file_path

def aes_decrypt_file(encrypted_file_path, key):
    # Read encrypted file
    with open(encrypted_file_path, 'rb') as enc_file:
        iv = enc_file.read(AES.block_size) 
        ciphertext = enc_file.read() 

    # Decrypt ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Save decrypted file
    decrypted_file_path = encrypted_file_path[:-4]
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_file_path

def generate_AES_key():
   key = get_random_bytes(32)
   return key

# General Hashing SHA 256
def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            for byte_block in iter(lambda: file.read(4096), b""): 
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "File Not Found"
    except Exception as e:
        return f"An error occurred: {e}"

# Password functions
def store_password(username, password, filename="db_pw.txt"):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with open(filename, "a") as file:
        file.write(f"{username}:{hashed_password}\n")

def load_stored_password(username, filename="db_pw.txt"):
    try:
        with open(filename, "r") as file:
            for line in file:
                stored_username, stored_hash = line.strip().split(":")
                if stored_username == username:
                    return stored_hash.encode()
    except FileNotFoundError:
        print("Password file not found.")
    except ValueError:
        print("Invalid password file format.")
    return None

def verify_password(username, password, filename="db_pw.txt"):
    stored_hash = load_stored_password(username, filename)
    if stored_hash is None:
        return False
    return bcrypt.checkpw(password.encode(), stored_hash)
    
# File Path Database functions
database_lock = threading.Lock()

def load_database(filename="db_filepaths.txt"):
    try:
        with database_lock:
            if not os.path.exists(filename):
                return {"file_index": {}, "peers": {}}
            with open(filename, "r") as db_file:
                return json.load(db_file)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error loading database: {e}")
        return {"file_index": {}, "peers": {}}

def save_database(data, filename="db_filepaths.txt"):
    try:
        temp_file = filename + ".tmp"
        with database_lock:
            with open(temp_file, "w") as db_file:
                json.dump(data, db_file, indent=4)
            os.replace(temp_file, filename)
    except OSError as e:
        print(f"Error saving database: {e}")

# RSA Functions
def generate_RSA_keypair(key_size=2048):
    pass

def rsa_encrypt(data, public_key):
    pass

def rsa_decrypt(ciphertext, private_key):
    pass

def sign_data_rsa(data, private_key):
    pass

def verify_signature_rsa(data, signature, public_key):
    pass

# DSA Functions
def generate_DSA_keypair(key_size=2048):
    pass

def sign_data_dsa(data, private_key):
    pass

def verify_signature_dsa(data, signature, public_key):
    pass

# Key Storage
def save_key(key, file_path):
    pass

def load_key(file_path):
    pass
