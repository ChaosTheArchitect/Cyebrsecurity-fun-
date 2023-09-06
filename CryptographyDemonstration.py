from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

class AESCrypto:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), 16))
        return iv + ciphertext

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), 16).decode()

def md5_cracker(hash_to_crack, dictionary_file):
    with open(dictionary_file, 'r') as file:
        for line in file:
            word = line.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
                return word
    return None

if __name__ == "__main__":
    # AES Encryption & Decryption Demo
    key = get_random_bytes(16)
    aes = AESCrypto(key)
    encrypted_data = aes.encrypt("Hello, World!")
    decrypted_data = aes.decrypt(encrypted_data)
    print("Encrypted Data:", encrypted_data)
    print("Decrypted Data:", decrypted_data)

    # MD5 Cracking Demo
    md5_hash = hashlib.md5("secret".encode()).hexdigest()
    cracked_password = md5_cracker(md5_hash, "../redteamprojects/dictionary.txt")
    if cracked_password:
        print(f"Cracked MD5 Hash: The password is '{cracked_password}'")
    else:
        print("Failed to crack the MD5 hash.")
