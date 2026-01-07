"""
Module xuất dữ liệu từ database thành file CSV và mã hóa
"""

import csv
import os
from datetime import datetime
import oracledb


def export_table_to_csv(conn, table_name, output_csv, schema_prefix="LOCB2"):
    """
    Xuất dữ liệu từ bảng thành file CSV.
    
    Args:
        conn: Kết nối Oracle
        table_name: Tên bảng (ví dụ: USERS, INVOICES)
        output_csv: Đường dẫn file CSV đầu ra
        schema_prefix: Schema sở hữu bảng (mặc định LOCB2)
    
    Returns:
        (success, message, row_count)
    """
    try:
        cur = conn.cursor()
        
        # Query dữ liệu
        full_table_name = f"{schema_prefix}.{table_name}"
        cur.execute(f"SELECT * FROM {full_table_name}")
        
        # Lấy tên cột
        columns = [desc[0] for desc in cur.description]
        rows = cur.fetchall()
        
        # Ghi CSV
        os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(columns)  # Header
            writer.writerows(rows)    # Data
        
        cur.close()
        return True, f"✓ Exported {len(rows)} rows từ {table_name}", len(rows)
        
    except Exception as e:
        return False, f"✗ Lỗi xuất dữ liệu: {e}", 0


def export_table_with_where(conn, table_name, where_clause, output_csv, schema_prefix="LOCB2"):
    """
    Xuất dữ liệu từ bảng với điều kiện WHERE.
    
    Args:
        conn: Kết nối Oracle
        table_name: Tên bảng
        where_clause: Điều kiện WHERE (ví dụ: "ID > 5 AND STATUS = 'ACTIVE'")
        output_csv: Đường dẫn file CSV đầu ra
        schema_prefix: Schema sở hữu bảng
    
    Returns:
        (success, message, row_count)
    """
    try:
        cur = conn.cursor()
        
        # Query dữ liệu
        full_table_name = f"{schema_prefix}.{table_name}"
        sql = f"SELECT * FROM {full_table_name}"
        if where_clause:
            sql += f" WHERE {where_clause}"
        
        cur.execute(sql)
        
        # Lấy tên cột
        columns = [desc[0] for desc in cur.description]
        rows = cur.fetchall()
        
        # Ghi CSV
        os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(columns)  # Header
            writer.writerows(rows)    # Data
        
        cur.close()
        return True, f"✓ Exported {len(rows)} rows từ {table_name}", len(rows)
        
    except Exception as e:
        return False, f"✗ Lỗi xuất dữ liệu: {e}", 0


def encrypt_file_des(input_file, output_file, conn):
    """
    Mã hóa file bằng DES sử dụng function Oracle.
    
    Args:
        input_file: Đường dẫn file nguồn (CSV)
        output_file: Đường dẫn file mã hóa (.enc)
        conn: Kết nối Oracle (để gọi des_encrypt_raw)
    
    Returns:
        (success, message)
    """
    try:
        # Đọc file CSV
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Mã hóa dùng Oracle function
        cur = conn.cursor()
        cur.execute("""
            SELECT des_encrypt_raw(:data) FROM dual
        """, {'data': data})
        
        encrypted = cur.fetchone()[0]
        cur.close()
        
        # Ghi file mã hóa
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, 'wb') as f:
            f.write(encrypted)
        
        return True, f"✓ File mã hóa: {output_file}"
        
    except Exception as e:
        return False, f"✗ Lỗi mã hóa: {e}"


def decrypt_file_des(input_file, output_file, conn):
    """
    Giải mã file DES.
    
    Args:
        input_file: Đường dẫn file mã hóa (.enc)
        output_file: Đường dẫn file giải mã (CSV)
        conn: Kết nối Oracle
    
    Returns:
        (success, message)
    """
    try:
        # Đọc file mã hóa
        with open(input_file, 'rb') as f:
            encrypted = f.read()
        
        # Giải mã dùng Oracle function
        cur = conn.cursor()
        cur.execute("""
            SELECT des_decrypt_raw(:data) FROM dual
        """, {'data': encrypted})
        
        decrypted = cur.fetchone()[0]
        cur.close()
        
        # Ghi file giải mã
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, 'wb') as f:
            f.write(decrypted)
        
        return True, f"✓ File giải mã: {output_file}"
        
    except Exception as e:
        return False, f"✗ Lỗi giải mã: {e}"


def export_and_encrypt(conn, table_name, output_csv, output_enc, schema_prefix="LOCB2", where_clause=None):
    """
    Một bước xuất bảng và mã hóa.
    
    Returns:
        (success, message)
    """
    # 1. Xuất CSV
    if where_clause:
        success, msg, _ = export_table_with_where(conn, table_name, where_clause, output_csv, schema_prefix)
    else:
        success, msg, _ = export_table_to_csv(conn, table_name, output_csv, schema_prefix)
    
    if not success:
        return False, msg
    
    # 2. Mã hóa CSV
    success, msg = encrypt_file_des(output_csv, output_enc, conn)
    
    if success:
        # Xóa file CSV gốc để chỉ giữ file mã hóa
        try:
            os.remove(output_csv)
        except:
            pass
    
    return success, msg
