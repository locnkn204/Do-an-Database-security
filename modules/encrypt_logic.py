from .crypto_rsa import rsa_encrypt_file, rsa_decrypt_file
from .crypto_des import oracle_des_encrypt_file, oracle_des_decrypt_file
from .crypto_rsa_oracle import oracle_rsa_encrypt_file, oracle_rsa_decrypt_file
from .crypto_des_python import python_des_encrypt_file, python_des_decrypt_file
from .crypto_additive import additive_encrypt_file, additive_decrypt_file
import os


def _log_encryption_action(conn, username, algo, action, src_file):
    """Ghi log hành động mã hóa/giải mã vào bảng LOGS"""
    if not conn or not username:
        return
    
    try:
        cur = conn.cursor()
        
        # Lấy USER_ID
        cur.execute("SELECT ID FROM LOCB2.USERS WHERE USERNAME = :uname", {'uname': username.upper()})
        result = cur.fetchone()
        if not result:
            print(f"⚠️ Không tìm thấy USER_ID cho {username}")
            return
        
        user_id = result[0]
        filename = os.path.basename(src_file)
        
        # Tạo message log
        if action == "encrypt":
            log_action = f"Encrypt: {algo.upper()} - Mã hóa file '{filename}'"
        elif action == "decrypt":
            log_action = f"Decrypt: {algo.upper()} - Giải mã file '{filename}'"
        else:
            log_action = f"Crypto: {algo.upper()} - {action} file '{filename}'"
        
        # Insert vào LOGS
        cur.execute("""
            INSERT INTO LOCB2.LOGS (USER_ID, ACTION, TIMESTAMP)
            VALUES (:uid, :action, SYSTIMESTAMP)
        """, {'uid': user_id, 'action': log_action})
        
        conn.commit()
        print(f"✅ Đã ghi log: {log_action}")
        
    except Exception as e:
        print(f"⚠️ Không ghi được log mã hóa: {e}")


def run_encryption(algo, action, src, dest, key_raw=None, conn=None, layer="app", username=None):
    """
    Thực hiện mã hóa/giải mã
    
    Args:
        algo: Thuật toán (DES, RSA, ADDITIVE)
        action: Hành động (encrypt, decrypt)
        src: File nguồn
        dest: File đích
        key_raw: Khóa (string)
        conn: Database connection
        layer: Tầng thực thi ("app" = Python, "db" = Oracle)
        username: Username hiện tại (để ghi log)
    """
    
    # Biến để track xem có thành công không
    success = False

    # ================= DES =================
    if algo == "DES":
        # ========== TẦNG ỨNG DỤNG (PYTHON) ==========
        if layer == "app":
            if not key_raw:
                success = True
            elif action == "decrypt":
                python_des_decrypt_file(src, dest, key_raw)
                success = True
            if action == "encrypt":
                python_des_encrypt_file(src, dest, key_raw)
                success = True
            elif action == "decrypt":
                python_des_decrypt_file(src, dest, key_raw)
                success = True
            else:
                raise ValueError("Action DES không hợp lệ")
        
        # ========== TẦNG DATABASE (ORACLE) ==========
        elif layer == "db":
            if conn is None:
                raise ValueError("DES (Oracle) cần database connection")

            if action == "encrypt":
                oracle_des_encrypt_file(conn, src, dest, key_raw=key_raw)
                success = True
            elif action == "decrypt":
                oracle_des_decrypt_file(conn, src, dest, key_raw=key_raw)
                success = True
            else:
                raise ValueError("Action DES không hợp lệ")
        
        else:
            raise ValueError(f"Tầng không hợp lệ: {layer}")
    
    # ================= MÃ HÓA CỘNG (ADDITIVE) =================
    elif algo == "ADDITIVE":
        # Chỉ có tầng ứng dụng (Python)
        if layer != "app":
            raise ValueError("Mã hóa cộng chỉ hỗ trợ tầng ứng dụng (Python)")
        
        # key_raw là số dịch chuyển (shift)
        try:
            shift = int(key_raw) if key_raw else 3
        except ValueError:
            raise ValueError("Khóa mã hóa cộng phải là số nguyên (shift)")
        
        if action == "encrypt":
            additive_encrypt_file(src, dest, shift)
            success = True
        elif action == "decrypt":
            additive_decrypt_file(src, dest, shift)
            success = True
        else:
            raise ValueError("Action mã hóa cộng không hợp lệ")

    # ================= RSA =================
    elif algo == "RSA":
        
        # ========== TẦNG ỨNG DỤNG (PYTHON) ==========
        if layer == "app":
            if not key_raw.strip().startswith("-----BEGIN"):
                raise ValueError("Khóa RSA (Python) phải có định dạng PEM (-----BEGIN...)")

            # Convert string to bytes
            key_bytes = key_raw.strip().encode('utf-8')

            if action == "encrypt":
                success = True

            elif action == "decrypt":
                # Decrypt cần PRIVATE KEY
                if b"PRIVATE KEY" not in key_bytes:
                    raise ValueError("Giải mã cần PRIVATE KEY (không phải PUBLIC KEY)")
                rsa_decrypt_file(src, dest, key_bytes)
                success = True
                # Decrypt cần PRIVATE KEY
                if b"PRIVATE KEY" not in key_bytes:
                    raise ValueError("Giải mã cần PRIVATE KEY (không phải PUBLIC KEY)")
                rsa_decrypt_file(src, dest, key_bytes)

            else:
                raise ValueError("Action RSA không hợp lệ")
        
        # ========== TẦNG DATABASE (ORACLE) ==========
        elif layer == "db":
            if conn is None:
                raise ValueError("RSA (Oracle) cần database connection")
            
            if not key_raw.strip():
                raise ValueError("Cần nhập khóa RSA")
            
            # Oracle trả về base64 thuần (không có PEM header)
            # Chỉ cần kiểm tra độ dài hợp lệ
            key_clean = key_raw.strip()
            
            # Loại bỏ marker nếu có (****publicKey start**** ... ****publicKey end****)
            if "****" in key_clean:
                # Tìm nội dung giữa các marker
                start_idx = key_clean.find("****")
                if start_idx >= 0:
                    # Tìm marker kết thúc
                    end_marker_start = key_clean.rfind("****")
                    if end_marker_start > start_idx:
                        # Lấy nội dung giữa 2 marker
                        key_content = key_clean[start_idx:end_marker_start]
                        # Loại bỏ text marker
                        key_content = key_content.replace("****publicKey start****", "")
                        key_content = key_content.replace("****privateKey start****", "")
                        key_content = key_content.replace("****publicKey end****", "")
                        key_content = key_content.replace("****privateKey end****", "")
                        key_clean = key_content.strip()
            
            # Validate: Oracle RSA key (base64) thường dài 200-2000 ký tự
            # Validate: Oracle RSA key (base64) thường dài 200-2000 ký tự
            if len(key_clean) < 100:
                raise ValueError(
                    f"Khóa RSA quá ngắn (chỉ {len(key_clean)} ký tự).\n"
                    "Khóa hợp lệ phải dài ít nhất 100 ký tự."
                )
            
            # Gọi Oracle Java functions để encrypt/decrypt
            if action == "encrypt":
                oracle_rsa_encrypt_file(conn, src, dest, key_clean)
                success = True
            
            elif action == "decrypt":
                oracle_rsa_decrypt_file(conn, src, dest, key_clean)
                success = True
            
            else:
                raise ValueError("Action RSA không hợp lệ")
        
        else:
            raise ValueError(f"Tầng không hợp lệ: {layer}")

    else:
        raise ValueError("Thuật toán không hợp lệ")
    
    # ✅ GHI LOG SAU KHI THÀNH CÔNG
    if success:
        _log_encryption_action(conn, username, algo, action, src)
