import csv
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Path to the CSV file where the encryption keys are stored
KEY_FILE = 'user_credentials.csv'

def generate_fernet_key():
    # Generate a random salt and key
    salt = os.urandom(16)
    password = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    # Encode both key and salt in base64 separately
    encoded_key = base64.b64encode(key).decode('utf-8')
    encoded_salt = base64.b64encode(salt).decode('utf-8')
    return encoded_key, encoded_salt

def load_or_create_key(encrypted_username):
    try:
        with open(KEY_FILE, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row and row[0] == encrypted_username:  # Direct comparison with the encrypted username
                    key_bytes = base64.b64decode(row[5])
                    salt_bytes = base64.b64decode(row[6])
                    return key_bytes, salt_bytes
    except FileNotFoundError:
        logging.error("User credentials file not found.")
    except Exception as e:
        logging.error(f"Error reading user credentials: {e}")

    # If user key not found, generate a new one
    encoded_key, encoded_salt = generate_fernet_key()
    store_key(encrypted_username, encoded_key, encoded_salt)
    return base64.b64decode(encoded_key), base64.b64decode(encoded_salt)



def store_key(username, encoded_key, encoded_salt):
                try:
                    found = False
                    rows = []
                    filepath = 'user_credentials.csv'
                    if os.path.exists(filepath):
                        with open(filepath, 'r+', newline='') as csvfile:
                            reader = csv.reader(csvfile)
                            rows = list(reader)
                            for index, row in enumerate(rows):
                                if len(row) < 7:
                                    continue  # Ensure all rows have at least 7 elements
                                if row[0] == username:
                                    row[5] = encoded_key  # Update the key
                                    row[6] = encoded_salt  # Update the salt
                                    found = True
                                    break

                    with open(filepath, 'w', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        if not found:
                            # Append a new user if not found, ensure the new row also has exactly 7 columns
                            new_row = [username, '', '', '', '', encoded_key, encoded_salt]
                            rows.append(new_row)
                        writer.writerows(rows)  # Write all rows back to the CSV
                except Exception as e:
                    print(f"Error storing key: {e}")


def encrypt_data(data, key, salt):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    logging.debug(f'Encrypt: Data={data}, Key={base64.b64encode(key)}, IV={base64.b64encode(iv)}, Encrypted={base64.b64encode(encrypted)}')
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_data(encrypted_data, key, salt):
    try:
         # Re-derive key from salt
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_data) + unpadder.finalize()
        logging.debug(f'Decrypt: Key={base64.b64encode(key)}, IV={base64.b64encode(iv)}, Decrypted={decrypted}')
        return decrypted.decode('utf-8')
    except Exception as e:
        logging.error(f'Error during decryption: {str(e)}')
        raise



