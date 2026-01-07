"""
Mã hóa cộng (Additive Cipher / Caesar Cipher) - Tầng ứng dụng
"""


def additive_encrypt_file(input_path: str, output_path: str, shift: int = 3) -> None:
    """
    Mã hóa file bằng thuật toán cộng (Caesar Cipher)
    
    Args:
        input_path: Đường dẫn file gốc
        output_path: Đường dẫn file mã hóa
        shift: Số dịch chuyển (mặc định = 3)
    """
    # Đọc dữ liệu
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Mã hóa: mỗi byte cộng thêm shift
    shift = shift % 256  # Đảm bảo trong phạm vi byte
    ciphertext = bytes((b + shift) % 256 for b in plaintext)
    
    # Ghi file
    with open(output_path, 'wb') as f:
        f.write(ciphertext)


def additive_decrypt_file(input_path: str, output_path: str, shift: int = 3) -> None:
    """
    Giải mã file bằng thuật toán cộng (Caesar Cipher)
    
    Args:
        input_path: Đường dẫn file mã hóa
        output_path: Đường dẫn file gốc
        shift: Số dịch chuyển (mặc định = 3)
    """
    # Đọc dữ liệu mã hóa
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    
    # Giải mã: mỗi byte trừ đi shift
    shift = shift % 256  # Đảm bảo trong phạm vi byte
    plaintext = bytes((b - shift) % 256 for b in ciphertext)
    
    # Ghi file
    with open(output_path, 'wb') as f:
        f.write(plaintext)


def additive_encrypt_text(text: str, shift: int = 3) -> str:
    """
    Mã hóa text (chỉ chữ cái, giữ nguyên ký tự khác)
    
    Args:
        text: Text gốc
        shift: Số dịch chuyển (mặc định = 3)
    
    Returns:
        str: Text mã hóa
    """
    result = []
    for char in text:
        if char.isalpha():
            # Xác định base (A hoặc a)
            base = ord('A') if char.isupper() else ord('a')
            # Dịch chuyển trong phạm vi 26 chữ cái
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            # Giữ nguyên ký tự không phải chữ cái
            result.append(char)
    return ''.join(result)


def additive_decrypt_text(text: str, shift: int = 3) -> str:
    """
    Giải mã text (chỉ chữ cái, giữ nguyên ký tự khác)
    
    Args:
        text: Text mã hóa
        shift: Số dịch chuyển (mặc định = 3)
    
    Returns:
        str: Text gốc
    """
    # Giải mã = mã hóa với shift ngược
    return additive_encrypt_text(text, -shift)
