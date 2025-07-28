import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 100_000

def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - len(data) % 16
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]  # data = hello\x03\x03\x03, data[-1] = 3, padding_len = 3 
    return data[:-padding_len] #data[: -3] = hello

def derive_key_iv(password: str, salt: bytes, iv_len: int):
    key_iv = PBKDF2(password,salt, dkLen=iv_len + KEY_SIZE, count=PBKDF2_ITERATIONS)
    return key_iv[:KEY_SIZE], key_iv[KEY_SIZE:]

def encrypt(data: bytes, password: str, mode: str) -> bytes:
    salt = get_random_bytes(16)

    if mode == "CBC":
        key, iv = derive_key_iv(password, salt, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data))
        return b"CBC" + salt + ciphertext

    elif mode == "CFB":
        key, iv = derive_key_iv(password, salt, 16)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(data)
        return b"CFB" + salt + ciphertext

    elif mode == "OFB":
        key, iv = derive_key_iv(password, salt, 16)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        ciphertext = cipher.encrypt(data)
        return b"OFB" + salt + ciphertext

    elif mode == "CTR":
        key, nonce = derive_key_iv(password, salt, 8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(data)
        return b"CTR" + salt + ciphertext

    elif mode == "GCM":
        key, nonce = derive_key_iv(password, salt, 12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return b"GCM" + salt + ciphertext + tag
    
def decrypt(enc_data: bytes, password: str, expected_mode: str = None) -> bytes:
    mode = enc_data[:3].decode()
    salt = enc_data[3:19]
    body = enc_data[19:]

    if expected_mode is not None and mode != expected_mode:
        raise ValueError(f"Expected mode is {expected_mode}, but data encypted with {mode} mode")
    
    if mode == "CBC":
        key, iv = derive_key_iv(password, salt, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(body))

    elif mode == "CFB":
        key, iv = derive_key_iv(password, salt, 16)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(body)

    elif mode == "OFB":
        key, iv = derive_key_iv(password, salt, 16)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        return cipher.decrypt(body)

    elif mode == "CTR":
        key, nonce = derive_key_iv(password, salt, 8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(body)

    elif mode == "GCM":
        key, nonce = derive_key_iv(password, salt, 12)
        ciphertext = body[:-16]
        tag = body[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    
def main():
    operation = input("Encrypt or decrypt? (e/d): ").lower()
    while operation not in ("e", "d"):
        operation = input("Invalid selection. Please retry (e/d): ")
    mode = input("AES mode (CBC, CFB, OFB, CTR, GCM): ").upper()
    while mode not in ("CBC", "CFB", "OFB", "CTR", "GCM"):
        mode = input("Please enter a valid value (CBC, CFB, OFB, CTR, GCM): ").upper()
    password = input("Password: ")

    try:
        if operation == "e":
            plaintext = input("Metin giriniz: ")
            data = plaintext.encode("utf-8")
            encrypted = encrypt(data, password, mode=mode)
            print("Encrypted (base64):", base64.b64encode(encrypted).decode())

        elif operation == "d":
            encrypted_b64 = input("Şifreli metni (base64) giriniz: ")
            encrypted_bytes = base64.b64decode(encrypted_b64)
            decrypted = decrypt(encrypted_bytes, password, expected_mode=mode)
            print("Decrypted data:", decrypted.decode("utf-8"))

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
if __name__ == "__main__":
    main()
