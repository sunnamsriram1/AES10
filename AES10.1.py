import requests
import datetime
import pytz
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Coded by string
coded_by = "SUNNAM_SRIRAM_1"

# Function to print the banner once

#colorama.init()


def banner():
    print("""
    \033[41m=[===> Mr. Tom | https://github.com/sunnamsriram1 <===]=\n\033[0m""")
banner()



# ANSI escape codes for text colors
class colors:
    # Reset
    RESET = '\033[0m'

    # Regular colors
    BLACK = '\033[0;30m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'

    # Bold colors
    BOLD_BLACK = '\033[1;30m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_PURPLE = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'

# Example usage
# print(colors.RED + "This is red text!" + colors.RESET)
# print(colors.BOLD_GREEN + "This is bold green text!" + colors.RESET)



coded_by = "SUNNAM_SRIRAM_1"

def print_banner():
    india_timezone = pytz.timezone('Asia/Kolkata')
    current_time = datetime.datetime.now(india_timezone).strftime("%Y-%m-%d %I:%M:%S.%f %p")[:-3]
    banner = f"""\t<ul>
        <li>{Fore.YELLOW}Coded by</li>
        <li>{Fore.WHITE}{coded_by}</li>
        <li>{Fore.GREEN}Today (India Time): {current_time}</li>
    </ul>\n\n"""
    print(banner)

print_banner()














import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

DATA_FILE = "encrypted_data.json"

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> dict:
    """Encrypt data using AES-256 with a user-defined password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)

    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(encrypted_data).decode()
    }

def decrypt_data(encrypted: dict, password: str) -> bytes:
    """Decrypt stored encrypted data using the user-defined password."""
    salt = base64.b64decode(encrypted["salt"])
    iv = base64.b64decode(encrypted["iv"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    
    try:
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except:
        print(Fore.RED + "[X] Incorrect password!")
        return None

def save_encrypted_data(new_entry: dict):
    """Save encrypted data without overwriting previous entries."""
    data_list = []

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                data_list = json.load(f)
                if not isinstance(data_list, list):
                    data_list = []
            except json.JSONDecodeError:
                data_list = []

    data_list.append(new_entry)

    with open(DATA_FILE, "w") as f:
        json.dump(data_list, f, indent=2)
    
    print(Fore.GREEN + f"[✔] Encrypted data saved to {DATA_FILE}")

def load_encrypted_data() -> list:
    """Load encrypted data from a JSON file."""
    if not os.path.exists(DATA_FILE):
        print(Fore.RED + "[X] No encrypted data found!")
        return None
    with open(DATA_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(Fore.RED + "[X] Error reading encrypted data file!")
            return None

# ---- Main Program ----
try:
    while True:
        print("\n" + Fore.CYAN + "[1] Encrypt Data")
        print(Fore.CYAN + "[2] Decrypt Stored Data")
        print(Fore.CYAN + "[3] Exit")
        choice = input(Fore.YELLOW + "\n[?] Select an option: ")

        if choice == "1":
            try:
                user_data = input(Fore.CYAN + "\n[?] Enter text to encrypt: ").encode()
                data_password = input(Fore.YELLOW + "[?] Set a password for this data: ")
                encrypted_data = encrypt_data(user_data, data_password)
                save_encrypted_data(encrypted_data)
            except KeyboardInterrupt:
                print(Fore.RED + "\n[X] Encryption canceled!")
                continue  # Go back to the menu

        elif choice == "2":
            try:
                encrypted_list = load_encrypted_data()
                if encrypted_list:
                    data_password = input(Fore.YELLOW + "[?] Enter the password for this data: ")
                    for encrypted_data in encrypted_list:
                        decrypted_data = decrypt_data(encrypted_data, data_password)
                        if decrypted_data:
                            print(Fore.GREEN + f"\n[✔] Decrypted Text: {Style.BRIGHT}{decrypted_data.decode()}")
                            break
                    else:
                        print(Fore.RED + "[X] Incorrect password!")
            except KeyboardInterrupt:
                print(Fore.RED + "\n[X] Decryption canceled!")
                continue  # Go back to the menu

        elif choice == "3":
            print(Fore.YELLOW + "[!] Exiting program...")
            break

        else:
            print(Fore.RED + "[X] Invalid choice! Please enter 1, 2, or 3.")

except KeyboardInterrupt:
    print(Fore.YELLOW + "\n[!] Program exited by user.")
