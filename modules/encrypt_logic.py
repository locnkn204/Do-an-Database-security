from .crypto_des import des_encrypt_file, des_decrypt_file, des_generate_key
from .crypto_rsa import rsa_encrypt_file, rsa_decrypt_file, rsa_generate_keypair

def run_encryption(algo, action, src, dest, key_raw):
    if algo == "DES":
        key = bytes.fromhex(key_raw.strip())
        if len(key) != 8:
            raise ValueError("Khóa DES phải là hex 8 bytes.")
        if action == "encrypt":
            des_encrypt_file(src, dest, key)
        else:
            des_decrypt_file(src, dest, key)

    elif algo == "RSA":
        if action == "encrypt":
            rsa_encrypt_file(src, dest, key_raw.encode())
        else:
            rsa_decrypt_file(src, dest, key_raw.encode())

    else:
        raise ValueError("Thuật toán không hợp lệ.")