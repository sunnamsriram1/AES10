import os
import getpass
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password, salt=b"static_salt"):
    """Derives a 32-byte key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path, password):
    """Encrypt a file using a password."""
    try:
        key = derive_key(password)
        cipher = Fernet(key)

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = cipher.encrypt(file_data)

        with open(file_path + ".enc", "wb") as file:
            file.write(encrypted_data)

        print(f"[✔] Encrypted file saved as: {file_path}.enc")
    except FileNotFoundError:
        print("[X] Error: File not found.")
    except Exception as e:
        print(f"[X] Encryption failed: {e}")

def decrypt_file(file_path, password):
    """Decrypt an encrypted file using a password."""
    try:
        key = derive_key(password)
        cipher = Fernet(key)

        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = cipher.decrypt(encrypted_data)

        original_file = file_path.replace(".enc", "")
        with open(original_file, "wb") as file:
            file.write(decrypted_data)

        print(f"[✔] Decrypted file saved as: {original_file}")
    except FileNotFoundError:
        print("[X] Error: File not found.")
    except Exception:
        print("[X] Decryption failed! Invalid password or corrupted file.")

def main():
    try:
        while True:
            print("\n[1] Encrypt a File\n[2] Decrypt a File\n[3] Exit")
            choice = input("[?] Select an option: ").strip()

            if choice == "1":
                try:
                    file_path = input("[?] Enter the file path to encrypt: ").strip()
                    password = getpass.getpass("[?] Set a password: ")
                    encrypt_file(file_path, password)
                except KeyboardInterrupt:
                    print("\n[X] Operation canceled by user.")
                    continue
            elif choice == "2":
                try:
                    file_path = input("[?] Enter the encrypted file path: ").strip()
                    password = getpass.getpass("[?] Enter the decryption password: ")
                    decrypt_file(file_path, password)
                except KeyboardInterrupt:
                    print("\n[X] Operation canceled by user.")
                    continue
            elif choice == "3":
                print("[✔] Exiting program.")
                break
            else:
                print("[X] Invalid choice! Please enter 1, 2, or 3.")
    except KeyboardInterrupt:
        print("\n[X] Program terminated by user.")
    except Exception as e:
        print(f"[X] Unexpected error: {e}")

if __name__ == "__main__":
    main()
