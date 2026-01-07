"""
Module mã hóa RSA sử dụng Oracle Java Stored Functions

Lưu ý: 
- Tạo khóa: Gọi SELECT crypto.rsa_generate_keys trong Oracle
- Mã hóa/Giải mã: Có thể dùng Python HOẶC Oracle Java
- Oracle Java functions chỉ hỗ trợ text files
"""

def oracle_rsa_generate_keypair(conn) -> tuple:
    """
    Tạo cặp khóa RSA bằng Oracle SELECT
    
    Thực thi: SELECT GET_RSA_KEYS_WRAPPER() FROM dual
    
    Returns:
        tuple: (public_key, private_key) - base64 strings
    
    Note:
        GET_RSA_KEYS_WRAPPER return format: private_key***public_key hoặc khác
        Hàm sẽ tự động phân tách
    """
    cur = conn.cursor()
    
    try:
        keys_str = None
        
        # Cách 1: Gọi function không schema prefix
        try:
            cur.execute("SELECT GET_RSA_KEYS_WRAPPER() FROM dual")
            result = cur.fetchone()
            if result and result[0]:
                keys_str = result[0]
        except Exception as e1:
            # Cách 2: Thử với LOCB2 schema prefix
            try:
                cur.execute("SELECT LOCB2.GET_RSA_KEYS_WRAPPER() FROM dual")
                result = cur.fetchone()
                if result and result[0]:
                    keys_str = result[0]
            except Exception as e2:
                raise ValueError(
                    f"❌ Lỗi tạo khóa từ Oracle:\n{str(e2)}\n\n"
                    "📋 Kiểm tra:\n"
                    "1. Function GET_RSA_KEYS_WRAPPER đã được tạo chưa?\n"
                    "   CREATE OR REPLACE FUNCTION GET_RSA_KEYS_WRAPPER\n"
                    "   RETURN VARCHAR2\n"
                    "   IS ...\n\n"
                    "2. Test SQL: SELECT GET_RSA_KEYS_WRAPPER() FROM dual;\n"
                )
        
        # Xử lý nếu trả về error
        if not keys_str:
            raise ValueError("GET_RSA_KEYS_WRAPPER trả về NULL hoặc rỗng")
        
        if keys_str.startswith('Error:'):
            raise ValueError(f"Oracle function lỗi: {keys_str}")
        
        # Phân tách public/private key
        private_key = None
        public_key = None
        
        # Thử phân tách theo format: private_key***public_key
        if '***' in keys_str:
            parts = keys_str.split('***')
            if len(parts) == 2:
                private_key = parts[0].strip()
                public_key = parts[1].strip()
        
        # Nếu không có ***, thử phân tách theo kích thước
        # (Private key thường dài hơn public key)
        if not private_key or not public_key:
            # Tìm điểm phân tách có khả năng nhất
            # Public key thường: 300-500 chars
            # Private key thường: 1600-2000 chars
            
            # Thử tìm separator khác (|, ;, \n, etc)
            for sep in ['|', ';', '\n', '\r\n', ':::', '--']:
                if sep in keys_str:
                    parts = keys_str.split(sep)
                    if len(parts) >= 2:
                        # Lấy 2 phần lớn nhất
                        parts = sorted(parts, key=len, reverse=True)[:2]
                        if len(parts[0]) > len(parts[1]):
                            private_key = parts[0].strip()
                            public_key = parts[1].strip()
                        else:
                            public_key = parts[0].strip()
                            private_key = parts[1].strip()
                        break
            
            # Nếu vẫn không tìm được, chia đôi
            if not private_key or not public_key:
                mid = len(keys_str) // 2
                # Tìm separator gần mid point
                sep_pos = -1
                for i in range(mid - 100, mid + 100):
                    if i < len(keys_str) and keys_str[i:i+2] in ['--', '||', '**']:
                        sep_pos = i
                        break
                
                if sep_pos > 0:
                    private_key = keys_str[:sep_pos].strip()
                    public_key = keys_str[sep_pos+2:].strip()
                else:
                    # Fallback: chia đôi đơn giản
                    # Public key thường ngắn hơn
                    if len(keys_str.split()[0]) > len(keys_str.split()[-1]):
                        private_key = keys_str[:mid].strip()
                        public_key = keys_str[mid:].strip()
                    else:
                        public_key = keys_str[:mid].strip()
                        private_key = keys_str[mid:].strip()
        
        # Validate keys
        if not private_key or not public_key:
            raise ValueError("Không thể phân tách private key và public key từ kết quả")
        
        if len(private_key) < 100 or len(public_key) < 50:
            raise ValueError(
                f"Keys có vẻ không đúng:\n"
                f"- Private key length: {len(private_key)}\n"
                f"- Public key length: {len(public_key)}\n\n"
                f"Kết quả từ Oracle:\n{keys_str[:200]}..."
            )
        
        return public_key, private_key
        
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(
            f"❌ Lỗi bất ngờ khi tạo khóa từ Oracle:\n{str(e)}\n\n"
            "Vui lòng kiểm tra:\n"
            "1. Kết nối database OK?\n"
            "2. Function GET_RSA_KEYS_WRAPPER tồn tại?\n"
            "3. Quyền EXECUTE được cấp?"
        )
    finally:
        cur.close()


def oracle_rsa_encrypt_file(conn, input_path: str, output_path: str, public_key: str) -> None:
    """
    Mã hóa file bằng RSA procedure trong Oracle (Java)
    
    Args:
        conn: Database connection
        input_path: Đường dẫn file gốc (text file)
        output_path: Đường dẫn file mã hóa
        public_key: Public key (base64 string)
    """
    # Đọc file
    with open(input_path, 'r', encoding='utf-8') as f:
        plain_text = f.read()
    
    cur = conn.cursor()
    
    try:
        encrypted_text = cur.var(str, 4000)
        
        # Cách 1: Gọi procedure không schema prefix
        try:
            cur.callproc('ENCRYPT_RSA_WRAPPER', [plain_text, public_key, encrypted_text])
        except Exception as e1:
            # Cách 2: Thử với LOCB2 schema prefix
            try:
                cur.callproc('LOCB2.ENCRYPT_RSA_WRAPPER', [plain_text, public_key, encrypted_text])
            except Exception as e2:
                raise ValueError(
                    f"❌ Không thể gọi procedure ENCRYPT_RSA_WRAPPER!\n\n"
                    f"Lỗi: {str(e2)}\n\n"
                    "📋 Kiểm tra:\n"
                    "1. Procedure ENCRYPT_RSA_WRAPPER đã được tạo chưa?\n"
                    "   CREATE OR REPLACE PROCEDURE ENCRYPT_RSA_WRAPPER (\n"
                    "       p_plain_text IN VARCHAR2,\n"
                    "       p_public_key IN VARCHAR2,\n"
                    "       p_encrypted_text OUT VARCHAR2\n"
                    "   ) IS\n"
                    "   BEGIN\n"
                    "       p_encrypted_text := RSA_ENCRYPT_JAVA(p_plain_text, p_public_key);\n"
                    "   END ENCRYPT_RSA_WRAPPER;\n\n"
                    "2. Cấp quyền: GRANT EXECUTE ON LOCB2.ENCRYPT_RSA_WRAPPER TO PUBLIC;\n"
                )
        
        result = encrypted_text.getvalue()
        if not result:
            raise ValueError("ENCRYPT_RSA_WRAPPER trả về NULL")
        
        # Ghi file mã hóa
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Lỗi mã hóa RSA từ Oracle:\n{str(e)}")
    finally:
        cur.close()


def oracle_rsa_decrypt_file(conn, input_path: str, output_path: str, private_key: str) -> None:
    """
    Giải mã file bằng RSA procedure trong Oracle (Java)
    
    Args:
        conn: Database connection
        input_path: Đường dẫn file mã hóa
        output_path: Đường dẫn file gốc
        private_key: Private key (base64 string)
    """
    # Đọc file mã hóa
    with open(input_path, 'r', encoding='utf-8') as f:
        encrypted_text = f.read()
    
    cur = conn.cursor()
    
    try:
        plain_text = cur.var(str, 4000)
        
        # Cách 1: Gọi procedure không schema prefix
        try:
            cur.callproc('DECRYPT_RSA_WRAPPER', [encrypted_text, private_key, plain_text])
        except Exception as e1:
            # Cách 2: Thử với LOCB2 schema prefix
            try:
                cur.callproc('LOCB2.DECRYPT_RSA_WRAPPER', [encrypted_text, private_key, plain_text])
            except Exception as e2:
                raise ValueError(
                    f"❌ Không thể gọi procedure DECRYPT_RSA_WRAPPER!\n\n"
                    f"Lỗi: {str(e2)}\n\n"
                    "📋 Kiểm tra:\n"
                    "1. Procedure DECRYPT_RSA_WRAPPER đã được tạo chưa?\n"
                    "   CREATE OR REPLACE PROCEDURE DECRYPT_RSA_WRAPPER (\n"
                    "       p_encrypted_text IN VARCHAR2,\n"
                    "       p_private_key IN VARCHAR2,\n"
                    "       p_plain_text OUT VARCHAR2\n"
                    "   ) IS\n"
                    "   BEGIN\n"
                    "       p_plain_text := RSA_DECRYPT_JAVA(p_encrypted_text, p_private_key);\n"
                    "   END DECRYPT_RSA_WRAPPER;\n\n"
                    "2. Cấp quyền: GRANT EXECUTE ON LOCB2.DECRYPT_RSA_WRAPPER TO PUBLIC;\n"
                )
        
        result = plain_text.getvalue()
        if not result:
            raise ValueError("DECRYPT_RSA_WRAPPER trả về NULL")
        
        # Ghi file giải mã
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
            
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Lỗi giải mã RSA từ Oracle:\n{str(e)}")
    finally:
        cur.close()
