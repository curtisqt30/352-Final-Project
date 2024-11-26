# Cryptographic Algorithms
from Crypto.PublicKey import RSA, DSA  # For RSA and DSA key pair generation
from Crypto.Signature import pkcs1_15, DSS  # For RSA and DSA signature
from Crypto.Cipher import PKCS1_OAEP, AES  # For RSA and AES encryption
from Crypto.Hash import SHA256  # For hashing data (SHA-256)
from Crypto.Random import get_random_bytes  # For random bytes
import bcrypt # For password and salting

# Standard Libraries
import os  # For file operations
import hashlib  # For hashing 

# AES Functions
def aes_encrypt_file(file_path, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pass

def aes_decrypt_file(encrypted_file_path, key):
    pass

def generate_AES_key():
    pass

# General Hashing
def hash_file(file_path):
    pass

# Password functions
def store_password(username, password, filename="db.txt"): # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    with open(filename, "a") as file:
        file.write(f"{username},{hashed_password.decode()},{salt.decode()}\n")

def load_stored_password(username, filename="db.txt"): # Read the file and retrieve the stored hash and salt for the username
    with open(filename, "r") as file:
        for line in file:
            stored_username, stored_hash, stored_salt = line.strip().split(",")
            if stored_username == username:
                return stored_hash.encode(), stored_salt.encode()
    return None, None 

def verify_password(username, password, filename="db.txt"):  # Load the stored hash and salt, then verify the password
    stored_hash, stored_salt = load_stored_password(username, filename)
    if stored_hash is None:
        return False 
    return bcrypt.checkpw(password.encode(), stored_hash)

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
