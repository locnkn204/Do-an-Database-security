from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def des_generate_key():
    return get_random_bytes(8)

def des_encrypt_file(input_path, output_path, key: bytes):
    cipher = DES.new(key, DES.MODE_EAX)
    data = open(input_path, "rb").read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_path, "wb") as f:
        f.write(bytes([len(cipher.nonce)]))
        f.write(cipher.nonce)
        f.write(bytes([len(tag)]))
        f.write(tag)
        f.write(ciphertext)

def des_decrypt_file(input_path, output_path, key: bytes):
    raw = open(input_path, "rb").read()

    idx = 0
    nonce_len = raw[idx]; idx += 1
    nonce = raw[idx:idx+nonce_len]; idx += nonce_len
    tag_len = raw[idx]; idx += 1
    tag = raw[idx:idx+tag_len]; idx += tag_len
    ciphertext = raw[idx:]

    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    open(output_path, "wb").write(plaintext)