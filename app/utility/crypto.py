import os
from cryptography.fernet import Fernet

def get_fernet():
    # load once per‐process
    key = os.environ["APP_FERNET_KEY"]
    return Fernet(key.encode())

def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    f = get_fernet()
    token = f.encrypt(plaintext.encode())
    return token.decode()

def decrypt_secret(token: str) -> str:
    f = get_fernet()
    data = f.decrypt(token.encode())
    return data.decode()