
# AES Encryption Decryption Tool

This project is a Python-based application that encrypts text received from the user with various modes of the AES algorithm (CBC, CFB, OFB, CTR, GCM) and decrypts the encrypted data.

## Features

- **Encryption Modes:** CBC, CFB, OFB, CTR, GCM
- **Key Derivation with PBKDF2**
- **Encrypted data representation with Base64**
- **Padding for CBC**
- **Authentication tag in GCM mode**

## Requirement

- Python 3.6+
- [pycryptodome](https://pypi.org/project/pycryptodome/) library

For installation:
```bash
pip install pycryptodome
```

## Encryption

1. Select the encryption process by pressing the `e` key.
2. Select the mode (CBC, CFB, OFB, CTR, GCM).
3. Enter the password.
4. Enter the text to be encrypted.

You will receive a ciphertext in base64 format as output.


## Decryption

1. Press the `d` key to select the decryption process.
2. Select the same encryption mode.
3. Enter the same password.
4. Paste the encrypted (base64) text.

The decrypted text will be printed to the screen.

## Author

Yusuf İslam ÖZAYDIN / Kapatal

---

> This project was developed to learn and apply fundamental cryptography principles. Careful analysis and security auditing are required for real-world applications.
