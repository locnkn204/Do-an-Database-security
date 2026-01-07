"""
Mã hóa DES tầng ứng dụng (Python) - Sử dụng thư viện pycryptodome
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib


def _prepare_des_key(key_str: str) -> bytes:
    """
    Chuẩn bị khóa DES (8 bytes)
    
    Args:
        key_str: Khóa dạng string
    
    Returns:
        bytes: Khóa DES 8 bytes
    """
    if isinstance(key_str, bytes):
        key_bytes = key_str
    else:
        key_bytes = key_str.encode('utf-8')
    
    # DES cần đúng 8 bytes
    if len(key_bytes) == 8:
        return key_bytes
    elif len(key_bytes) < 8:
        # Pad với 0
        return key_bytes.ljust(8, b'\x00')
    else:
        # Hash rồi lấy 8 bytes đầu
        return hashlib.md5(key_bytes).digest()[:8]


def python_des_encrypt_file(input_path: str, output_path: str, key_str: str) -> None:
    """
    Mã hóa file bằng DES (Python)
    
    Args:
        input_path: Đường dẫn file gốc
        output_path: Đường dẫn file mã hóa
        key_str: Khóa DES (string)
    """
    # Chuẩn bị khóa
    key = _prepare_des_key(key_str)
    
    # Đọc dữ liệu
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Tạo cipher DES (CBC mode với IV = 0)
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00' * 8)
    
    # Padding dữ liệu để chia hết cho 8 bytes
    padded_data = pad(plaintext, DES.block_size)
    
    # Mã hóa
    ciphertext = cipher.encrypt(padded_data)
    
    # Ghi file
    with open(output_path, 'wb') as f:
        f.write(ciphertext)


def python_des_decrypt_file(input_path: str, output_path: str, key_str: str) -> None:
    """
    Giải mã file bằng DES (Python)
    
    Args:
        input_path: Đường dẫn file mã hóa
        output_path: Đường dẫn file gốc
        key_str: Khóa DES (string)
    """
    # Chuẩn bị khóa
    key = _prepare_des_key(key_str)
    
    # Đọc dữ liệu mã hóa
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    
    # Tạo cipher DES (CBC mode với IV = 0)
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00' * 8)
    
    # Giải mã
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Loại bỏ padding
    try:
        plaintext = unpad(padded_plaintext, DES.block_size)
    except ValueError as e:
        raise ValueError("Giải mã thất bại! Khóa có thể sai hoặc file không đúng định dạng.")
    
    # Ghi file
    with open(output_path, 'wb') as f:
        f.write(plaintext)
