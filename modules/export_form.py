"""
Form xuất và mã hóa dữ liệu từ bảng
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
from modules.export_encrypt import export_table_to_csv, export_table_with_where, encrypt_file_des, export_and_encrypt


def open_export_encrypt_form(parent, conn):
    """Mở form xuất dữ liệu và mã hóa"""
    
    if not conn:
        messagebox.showerror("Lỗi", "Không có kết nối database!")
        return
    
    dlg = tk.Toplevel(parent)
    dlg.title("📊 Export & Encrypt")
    dlg.geometry("600x450")
    dlg.transient(parent)
    dlg.grab_set()
    
    # --- Frame trên: Chọn bảng ---
    frame_select = ttk.LabelFrame(dlg, text="1. Chọn bảng", padding=10)
    frame_select.pack(fill="x", padx=10, pady=5)
    
    ttk.Label(frame_select, text="Tên bảng:").pack(side="left", padx=5)
    var_table = tk.StringVar(value="USERS")
    entry_table = ttk.Entry(frame_select, textvariable=var_table, width=30)
    entry_table.pack(side="left", padx=5)
    
    ttk.Label(frame_select, text="Schema:").pack(side="left", padx=5)
    var_schema = tk.StringVar(value="LOCB2")
    entry_schema = ttk.Entry(frame_select, textvariable=var_schema, width=15)
    entry_schema.pack(side="left", padx=5)
    
    # --- Frame giữa: Điều kiện WHERE ---
    frame_where = ttk.LabelFrame(dlg, text="2. Điều kiện (tùy chọn)", padding=10)
    frame_where.pack(fill="x", padx=10, pady=5)
    
    ttk.Label(frame_where, text="WHERE clause (ví dụ: ID > 5 AND STATUS = 'ACTIVE'):").pack(anchor="w", padx=5)
    text_where = tk.Text(frame_where, height=3, width=70)
    text_where.pack(padx=5, pady=5, fill="both", expand=True)
    
    # --- Frame lưu file ---
    frame_path = ttk.LabelFrame(dlg, text="3. Lưu file", padding=10)
    frame_path.pack(fill="x", padx=10, pady=5)
    
    var_output = tk.StringVar(value=os.path.expanduser("~/export_data.enc"))
    
    def select_output():
        file = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if file:
            var_output.set(file)
    
    ttk.Label(frame_path, text="Đường dẫn file (.enc):").pack(anchor="w", padx=5)
    ttk.Entry(frame_path, textvariable=var_output, width=70).pack(padx=5, pady=5, fill="x")
    ttk.Button(frame_path, text="Browse", command=select_output).pack(anchor="w", padx=5)
    
    # --- Frame nút tác vụ ---
    frame_actions = ttk.Frame(dlg, padding=10)
    frame_actions.pack(fill="x", padx=10, pady=5)
    
    def on_export_encrypt():
        table = var_table.get().strip()
        schema = var_schema.get().strip().upper()
        where = text_where.get("1.0", "end").strip()
        output = var_output.get().strip()
        
        if not table:
            messagebox.showwarning("Thiếu dữ liệu", "Nhập tên bảng!")
            return
        
        if not output:
            messagebox.showwarning("Thiếu dữ liệu", "Chọn đường dẫn file!")
            return
        
        try:
            # Xuất + mã hóa
            success, msg = export_and_encrypt(
                conn,
                table.upper(),
                output.replace(".enc", ".csv"),
                output,
                schema_prefix=schema,
                where_clause=where if where else None
            )
            
            if success:
                messagebox.showinfo("Thành công", msg)
                dlg.destroy()
            else:
                messagebox.showerror("Lỗi", msg)
        
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi xuất & mã hóa:\n{e}")

    
    def on_export_only():
        """Chỉ xuất thành CSV mà không mã hóa"""
        table = var_table.get().strip()
        schema = var_schema.get().strip().upper()
        where = text_where.get("1.0", "end").strip()
        output = var_output.get().strip().replace(".enc", ".csv")
        
        if not table:
            messagebox.showwarning("Thiếu dữ liệu", "Nhập tên bảng!")
            return
        
        try:
            if where:
                success, msg, rows = export_table_with_where(conn, table.upper(), where, output, schema)
            else:
                success, msg, rows = export_table_to_csv(conn, table.upper(), output, schema)
            
            if success:
                messagebox.showinfo("Thành công", msg)
                dlg.destroy()
            else:
                messagebox.showerror("Lỗi", msg)
        
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi xuất dữ liệu:\n{e}")
    
    ttk.Button(frame_actions, text="✅ Export & Encrypt", command=on_export_encrypt).pack(side="left", padx=5)
    ttk.Button(frame_actions, text="📄 Export CSV only", command=on_export_only).pack(side="left", padx=5)
    ttk.Button(frame_actions, text="❌ Cancel", command=dlg.destroy).pack(side="right", padx=5)
    
    # --- Info ---
    frame_info = ttk.Frame(dlg, padding=10)
    frame_info.pack(fill="both", expand=True, padx=10, pady=5)
    
    info_text = """
📌 Hướng dẫn:
  1. Nhập tên bảng (ví dụ: USERS, PROFILES, SECURE_FILES)
  2. (Tùy chọn) Thêm điều kiện WHERE để lọc dữ liệu
  3. Chọn đường dẫn lưu file (.enc)
  4. Click "Export & Encrypt"

⚠️ Lưu ý:
  - File CSV tạm sẽ được xóa sau khi mã hóa
  - File .enc có thể giải mã bằng chức năng "Mã hóa tập tin"
  - Sử dụng DES encryption (dùng Oracle function)
    """
    
    ttk.Label(frame_info, text=info_text, justify="left").pack(anchor="w")


def _open_kyso_with_preload(parent, file_path):
    """
    Mở ứng dụng ký số với file được preload
    
    Args:
        parent: Cửa sổ cha
        file_path: Đường dẫn file cần ký
    """
    if DigitalSignatureApp is None:
        messagebox.showerror("Lỗi",
            "Không thể tải ứng dụng ký số!\n\n"
            "Kiểm tra lại:\n"
            "- File appkyso.py có tồn tại trong thư mục Kyso không\n"
            "- Thư viện cryptography đã được cài đặt chưa: pip install cryptography")
        return
    
    if not os.path.exists(file_path):
        messagebox.showerror("Lỗi", f"File không tồn tại:\n{file_path}")
        return
    
    try:
        # Tạo cửa sổ mới cho ứng dụng ký số
        kyso_window = tk.Toplevel(parent)
        kyso_window.withdraw()  # Ẩn cửa sổ tạm thời
        
        # Khởi tạo ứng dụng ký số với cửa sổ mới
        app = DigitalSignatureApp(kyso_window)
        
        # ✨ Preload file vừa xuất vào danh sách uploaded_files
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_name)[1].upper()
            
            file_info = {
                'path': file_path,
                'name': file_name,
                'size': file_size,
                'extension': file_ext,
                'status': 'Chưa ký',
                'upload_date': __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'signed': False,
                'signature': None
            }
            
            app.uploaded_files.append(file_info)
            
            # Refresh UI để hiển thị file vừa preload
            if hasattr(app, 'refresh_file_list'):
                app.refresh_file_list()
            
            print(f"✅ Preload file thành công: {file_name}")
        except Exception as e:
            print(f"⚠️ Lỗi preload file: {e}")
        
        # Hiển thị cửa sổ
        kyso_window.deiconify()
        
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể mở ứng dụng ký số:\n{e}")

