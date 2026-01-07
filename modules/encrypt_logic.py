from .crypto_rsa import rsa_encrypt_file, rsa_decrypt_file
from .crypto_des import oracle_des_encrypt_file, oracle_des_decrypt_file


def run_encryption(algo, action, src, dest, key_raw=None, conn=None):

    # ================= DES (ORACLE) =================
    if algo == "DES":
        if conn is None:
            raise ValueError("DES cần Oracle connection")

        if action == "encrypt":
            oracle_des_encrypt_file(conn, src, dest)

        elif action == "decrypt":
            oracle_des_decrypt_file(conn, src, dest)

        else:
            raise ValueError("Action DES không hợp lệ")

    # ================= RSA (PYTHON) =================
    elif algo == "RSA":
        if not key_raw.strip().startswith("-----BEGIN"):
            raise ValueError("Khóa RSA phải là PEM")

        if action == "encrypt":
            rsa_encrypt_file(src, dest, key_raw)

        elif action == "decrypt":
            rsa_decrypt_file(src, dest, key_raw)

        else:
            raise ValueError("Action RSA không hợp lệ")

    else:
        raise ValueError("Thuật toán không hợp lệ")
