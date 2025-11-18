from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def rsa_generate_keypair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt_file(input_path, output_path, public_key_bytes):
    session_key = get_random_bytes(32)
    data = open(input_path, "rb").read()

    aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(data)
    nonce = aes.nonce

    pub = RSA.import_key(public_key_bytes)
    rsa = PKCS1_OAEP.new(pub)
    enc_session = rsa.encrypt(session_key)

    with open(output_path, "wb") as f:
        f.write(len(enc_session).to_bytes(2, "big"))
        f.write(enc_session)
        f.write(bytes([len(nonce)])); f.write(nonce)
        f.write(bytes([len(tag)])); f.write(tag)
        f.write(ciphertext)

def rsa_decrypt_file(input_path, output_path, private_key_bytes):
    raw = open(input_path, "rb").read()
    idx = 0

    enc_len = int.from_bytes(raw[idx:idx+2], "big")
    idx += 2
    enc_session = raw[idx:idx+enc_len]; idx += enc_len

    nonce_len = raw[idx]; idx += 1
    nonce = raw[idx:idx+nonce_len]; idx += nonce_len

    tag_len = raw[idx]; idx += 1
    tag = raw[idx:idx+tag_len]; idx += tag_len

    ciphertext = raw[idx:]

    priv = RSA.import_key(private_key_bytes)
    rsa = PKCS1_OAEP.new(priv)
    session_key = rsa.decrypt(enc_session)

    aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    open(output_path, "wb").write(plaintext)
