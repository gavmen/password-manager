from cryptography.fernet import Fernet
import base64
import os
from getpass import getpass
import json
import string
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.fernet import InvalidToken



def generate_key(master_password):
    salt = b'unsafestaticsalt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
    return key

def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')


def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    decrypted_data = f.decrypt(base64.urlsafe_b64decode(encrypted_data))
    return decrypted_data.decode('utf-8')

def save_passwords(encrypted_passwords, filename='passwords.enc'):
    with open(filename, 'w') as f:
        f.write(encrypted_passwords)

def load_passwords(filename='passwords.enc'):
    try:
        with open(filename, 'r') as f:
            encrypted_passwords = f.read()
        return encrypted_passwords
    except FileNotFoundError:
        return None

def get_master_key():
    master_password = getpass('Enter the master password: ')
    return generate_key(master_password)

def load_encrypted_data(filename='passwords.enc'):
    try:
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
        return encrypted_data
    except FileNotFoundError:
        return None

def add_password(service, plain_password, password_dict, key):
    encrypted_password = encrypt_data(plain_password, key)
    password_dict[service] = encrypted_password
    return password_dict

def retrieve_password(service, password_dict, key):
    encrypted_password = password_dict.get(service)
    if encrypted_password:
        return decrypt_data(encrypted_password, key)
    else:
        print(f"No password found for {service}.")
        return None

def generate_password(length=12):
    if length < 8:
        print("Password length should be at least 8 characters.")
        return None

    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def delete_password(service, password_dict, key):
    if service in password_dict:
        del password_dict[service]
        save_passwords(encrypt_data(json.dumps(password_dict), key))
        print(f"Password for {service} has been deleted.")
    else:
        print(f"No password found for {service}.")

def set_master_password():
    while True:
        master_password = getpass('Set your master password: ')
        password_confirm = getpass('Confirm your master password: ')
        if master_password == password_confirm:
            return master_password
        else:
            print("Passwords do not match. Please try again.")
            
def main():
    encrypted_passwords = load_encrypted_data()
    if encrypted_passwords:
        while True:
            key = get_master_key()
            try:
                password_dict = json.loads(decrypt_data(encrypted_passwords, key))
                break
            except (InvalidToken, ValueError):
                print("Invalid master password. Please try again.")
    else:
        master_password = set_master_password()
        key = generate_key(master_password)
        password_dict = {}
        save_passwords(encrypt_data(json.dumps(password_dict), key))

    while True:
        print("\nOptions: add, get, list, delete, quit")
        action = input("What would you like to do? ").strip().lower()
        if action == "add":
            service = input("Enter the service name: ")
            generate = input("Generate random password? (yes/no): ").strip().lower()
            if generate == 'yes':
                length = input("Enter the password length (default 12): ").strip()
                try:
                    length = int(length) if length else 12
                except ValueError:
                    print("Invalid length provided. Using default of 12.")
                    length = 12
                password = generate_password(length)
                print(f"Generated password: {password}")
            else:
                password = getpass("Enter the password for the service: ")
            password_dict = add_password(service, password, password_dict, key)
            save_passwords(encrypt_data(json.dumps(password_dict), key))
            print(f"Password added for {service}.")
        elif action == "get":
            service = input("Enter the service name: ")
            retrieved_password = retrieve_password(service, password_dict, key)
            if retrieved_password:
                print(f"The password for {service} is: {retrieved_password}")
        elif action == "list":
            print("Services stored:")
            for service in password_dict.keys():
                print(service)
        elif action == "delete":
            service = input("Enter the service name to delete: ")
            if service in password_dict:
                del password_dict[service]
                save_passwords(encrypt_data(json.dumps(password_dict), key))
                print(f"Password for {service} has been deleted.")
            else:
                print(f"No password found for {service}.")
        elif action == "quit":
            print("Exiting password manager.")
            break
        else:
            print("Invalid option. Try 'add', 'get', 'list', 'delete', or 'quit'.")

if __name__ == '__main__':
    main()
