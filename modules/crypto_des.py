def oracle_des_encrypt_file(conn, input_path, output_path, key_raw=None):
    """
    Mã hóa file bằng DES function trong Oracle
    
    Args:
        conn: Database connection
        input_path: Đường dẫn file gốc
        output_path: Đường dẫn file mã hóa
        key_raw: Khóa DES (string). Nếu None, sẽ dùng key mặc định
    """
    data = open(input_path, "rb").read()
    cur = conn.cursor()
    
    # Nếu không có key, dùng key mặc định
    if key_raw is None:
        key_raw = "DEFAULT_DES_KEY_1234567890"
    
    # Convert key to bytes (RAW)
    if isinstance(key_raw, str):
        key_bytes = key_raw.encode('utf-8')
    else:
        key_bytes = key_raw
    
    try:
        # Gọi FUNCTION DES_ENCRYPT_RAW với 2 tham số (data, key)
        cur.execute("""
            SELECT des_encrypt_raw(:1, :2) FROM dual
        """, [data, key_bytes])
        
        result = cur.fetchone()
        if result:
            encrypted = result[0]
            open(output_path, "wb").write(encrypted)
        else:
            raise ValueError("DES encryption returned no result")
    except Exception as e:
        raise ValueError(f"Lỗi mã hóa DES: {str(e)}")
    finally:
        cur.close()


def oracle_des_decrypt_file(conn, input_path, output_path, key_raw=None):
    """
    Giải mã file bằng DES function trong Oracle
    
    Args:
        conn: Database connection
        input_path: Đường dẫn file mã hóa
        output_path: Đường dẫn file gốc
        key_raw: Khóa DES (string). Nếu None, sẽ dùng key mặc định
    """
    data = open(input_path, "rb").read()
    cur = conn.cursor()
    
    # Nếu không có key, dùng key mặc định
    if key_raw is None:
        key_raw = "DEFAULT_DES_KEY_1234567890"
    
    # Convert key to bytes (RAW)
    if isinstance(key_raw, str):
        key_bytes = key_raw.encode('utf-8')
    else:
        key_bytes = key_raw
    
    try:
        # Gọi FUNCTION DES_DECRYPT_RAW với 2 tham số (data, key)
        cur.execute("""
            SELECT des_decrypt_raw(:1, :2) FROM dual
        """, [data, key_bytes])
        
        result = cur.fetchone()
        if result:
            decrypted = result[0]
            open(output_path, "wb").write(decrypted)
        else:
            raise ValueError("DES decryption returned no result")
    except Exception as e:
        raise ValueError(f"Lỗi giải mã DES: {str(e)}")
    finally:
        cur.close()