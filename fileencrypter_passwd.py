# File Encryption with Password
# if you have an error:   pip3 install --no-cache-dir --upgrade cryptography
# and pip3 install cryptography

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64
import getpass
import os.path
import pyfiglet
import configparser



def generate_salt(size=16):
    """Generate the salt used for key derivation,
    `size` is the length of the salt to generate"""
    return secrets.token_bytes(size)


def derive_key(salt, password):
    """Derive the key from the `password` using the passed `salt`
    We initialize the Scrypt algorithm by passing:
    The salt.
    The desired length of the key (32 in this case).
    n: CPU/Memory cost parameter, must be larger than 1 and be a power of 2.
    r: Block size parameter.
    p: Parallelization parameter.
    """
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1) # ori n=2**14
    return kdf.derive(password.encode())



def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()


def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """
    Core function to generate the key from passwd.
    Generates a key from a `password` and the salt.
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt
    and save it to "salt.salt"
    """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)    # derived = abgeleitet
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)
    print("File encrypted successfully")


def decrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try: # simple try except block to handle a wrong password
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("Invalid token, most likely the password is incorrect")
        return
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    print("File decrypted successfully")


def get_passwd():
    """password entry and verification"""
    password1 = getpass.getpass("enter the password for en/decryption: ")
    password2 = getpass.getpass("repeat the password for en/decryption: ")

    if password1 == password2:
        print('The password is verified')
        return password1
    else:
        print("error...password isn't the same")





### run ###
if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('config.cfg')
    #file = str(config['DEFAULT']['file'])
    ascii_banner = pyfiglet.figlet_format("FileEncrypter")
    print(ascii_banner)
    print("IMPORTANT: never lose your 'salt.salt', it is necessary to decrypt files!")
    enorde = int(input(" [1] = encrypt; [2] = decrypt; [3] = delete salt.salt; [0] = End --> "))
    if enorde == 1:
        print("enrypting...")
        password = get_passwd()
        if os.path.isfile("salt.salt"):
            print("slt exist, using salt.salt")
            key = generate_key(password, load_existing_salt=True)
        else:
            print("no salt File found, generating...")
            key = generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True)
        file = str(config['DEFAULT']['file'])
        encrypt(file, key)
    elif enorde == 2:
        print("decrypting...")
        password = get_passwd()
        if os.path.isfile("salt.salt"):
            print("slt exist, using salt.salt")
            key = generate_key(password, load_existing_salt=True)
        else:
            print("no salt File found, but it is necessary to decrypt...")
            #key = generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True)
        file = str(config['DEFAULT']['file'])
        decrypt(file, key)
    elif enorde == 3:
        confirmedel = str(input("if you want to delete salt.salt type 'yes' otherwise will break: "))
        if confirmedel == 'yes':
            os.remove("salt.salt")
            print("File deleted, closing...")
        else:
            print("nothing deleted, closing...")
    elif enorde == 0:
        print('closing...')
    else:
        print("error, wrong input!")


