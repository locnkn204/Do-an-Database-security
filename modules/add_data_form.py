"""
Module thêm dữ liệu vào bảng (dùng stored procedure)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import oracledb


def get_user_tables(conn):
    """Lấy danh sách bảng user có thể truy cập"""
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name FROM user_tables
            UNION
            SELECT table_name FROM all_tab_privs
            WHERE grantee = USER AND privilege = 'SELECT'
            ORDER BY table_name
        """)
        tables = [r[0] for r in cur.fetchall()]
        cur.close()
        return tables
    except Exception as e:
        print(f"❌ Lỗi lấy bảng: {e}")
        return []


def get_table_columns_info(conn, table_name):
    """
    Lấy danh sách cột insertable của bảng (loại bỏ GENERATED ALWAYS và cột có DEFAULT).
    
    Returns:
        [(col_name, col_type, nullable), ...]
    """
    try:
        cur = conn.cursor()
        
        # Lấy cột từ user_tab_columns
        cur.execute(f"""
            SELECT COLUMN_NAME, DATA_TYPE, NULLABLE, DATA_DEFAULT
            FROM user_tab_columns
            WHERE table_name = '{table_name.upper()}'
            ORDER BY column_id
        """)
        
        columns = cur.fetchall()
        cur.close()
        
        if not columns:
            # Thử lấy từ LOCB2 (nếu user không sở hữu)
            cur = conn.cursor()
            cur.execute(f"""
                SELECT COLUMN_NAME, DATA_TYPE, NULLABLE, DATA_DEFAULT
                FROM all_tab_columns
                WHERE owner = 'LOCB2' AND table_name = '{table_name.upper()}'
                ORDER BY column_id
            """)
            columns = cur.fetchall()
            cur.close()
        
        # Lọc cột: bỏ GENERATED ALWAYS và cột có DEFAULT
        result = []
        for col_name, col_type, nullable, data_default in columns:
            # Bỏ cột GENERATED ALWAYS
            if data_default and "GENERATED" in str(data_default).upper():
                continue
            
            # Bỏ cột có DEFAULT (trừ NULL default)
            if data_default and str(data_default).strip() not in ("", "NULL"):
                continue
            
            result.append((col_name, col_type, nullable))
        
        return result
        
    except Exception as e:
        print(f"❌ Lỗi lấy cột: {e}")
        return []


def insert_record_via_proc(conn, table_name, data_dict):
    """
    Gọi stored procedure để insert dữ liệu.
    
    Args:
        conn: Kết nối Oracle
        table_name: Tên bảng
        data_dict: Dictionary {column_name: value, ...} (tối đa 10 cột)
    
    Returns:
        (success, message)
    """
    try:
        if len(data_dict) > 10:
            return False, "✗ Tối đa 10 cột!"
        
        cur = conn.cursor()
        
        # Chuẩn bị tham số
        cols = list(data_dict.keys())
        vals = list(data_dict.values())
        
        # Tham số cho procedure: p_table_name, p_col1-10, p_val1-10, p_status OUT
        # Thứ tự: table_name, col1, val1, col2, val2, ..., col10, val10, status
        params = [table_name.upper()]
        
        # Thêm col/val pairs (tối đa 10 cặp)
        for i in range(10):
            if i < len(cols):
                params.append(cols[i])
                params.append(str(vals[i]))
            else:
                params.append(None)
                params.append(None)
        
        # OUT parameter cho status (phải là cursor hoặc variable, để callproc set giá trị)
        # Thay vì string rỗng, dùng var riêng
        status_var = cur.var(str)
        params.append(status_var)
        
        # Gọi procedure - Thử với schema prefix trước
        try:
            cur.callproc('LOCB2.insert_record_generic', params)
        except Exception as e1:
            # Nếu lỗi, thử không có prefix (trường hợp có synonym)
            if "PLS-00201" in str(e1) or "06550" in str(e1):
                try:
                    cur.callproc('insert_record_generic', params)
                except Exception as e2:
                    raise Exception(
                        f"❌ Không thể gọi procedure!\n\n"
                        f"Với LOCB2 prefix: {str(e1)[:200]}\n"
                        f"Không prefix: {str(e2)[:200]}\n\n"
                        f"💡 Giải pháp:\n"
                        f"1. Cấp quyền: GRANT EXECUTE ON LOCB2.insert_record_generic TO {conn.username};\n"
                        f"2. Hoặc tạo synonym: CREATE PUBLIC SYNONYM insert_record_generic FOR LOCB2.insert_record_generic;"
                    )
            else:
                raise e1
        
        # Lấy giá trị từ OUT parameter
        status = status_var.getvalue() if hasattr(status_var, 'getvalue') else str(status_var)
        conn.commit()
        cur.close()
        
        if status and "SUCCESS" in str(status):
            return True, f"✓ {status}"
        else:
            return False, f"✗ {status if status else 'Lỗi không xác định'}"
        
    except Exception as e:
        import traceback
        return False, f"✗ Lỗi gọi procedure: {e}\n{traceback.format_exc()}"


def open_add_data_form(parent, conn):
    """Mở form thêm dữ liệu"""
    
    if not conn:
        messagebox.showerror("Lỗi", "Không có kết nối database!")
        return
    
    dlg = tk.Toplevel(parent)
    dlg.title("📝 Add Data")
    dlg.geometry("600x500")
    dlg.transient(parent)
    dlg.grab_set()
    
    # --- Chọn bảng ---
    frame_select = ttk.LabelFrame(dlg, text="1. Chọn bảng", padding=10)
    frame_select.pack(fill="x", padx=10, pady=5)
    
    ttk.Label(frame_select, text="Bảng:").pack(side="left", padx=5)
    
    tables = get_user_tables(conn)
    combo_table = ttk.Combobox(frame_select, values=tables, state="readonly", width=40)
    combo_table.pack(side="left", padx=5, fill="x", expand=True)
    if tables:
        combo_table.current(0)
    
    # --- Nhập dữ liệu ---
    frame_data = ttk.LabelFrame(dlg, text="2. Nhập dữ liệu", padding=10)
    frame_data.pack(fill="both", expand=True, padx=10, pady=5)
    
    # Canvas scrollable
    canvas = tk.Canvas(frame_data)
    scrollbar = ttk.Scrollbar(frame_data, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    input_vars = {}  # {col_name: var}
    
    def on_table_select(event=None):
        """Khi chọn bảng, lấy cột và tạo input fields"""
        nonlocal input_vars
        
        # Xóa fields cũ
        for widget in scrollable_frame.winfo_children():
            widget.destroy()
        input_vars.clear()
        
        table = combo_table.get()
        if not table:
            return
        
        # Lấy cột
        columns = get_table_columns_info(conn, table)
        
        if not columns:
            ttk.Label(scrollable_frame, text=f"❌ Không lấy được cột từ {table}", foreground="red").pack(pady=10)
            return
        
        ttk.Label(scrollable_frame, text=f"Bảng: {table}", font=("Segoe UI", 11, "bold")).pack(pady=5)
        
        for col_name, col_type, nullable in columns:
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill="x", padx=5, pady=3)
            
            # Label
            label_text = col_name
            if nullable == 'N':
                label_text += " *"  # Hiển thị * cho cột bắt buộc
            ttk.Label(frame, text=label_text, width=20, anchor="e", foreground="red" if nullable == 'N' else "black").pack(side="left", padx=5)
            
            # Entry
            var = tk.StringVar()
            input_vars[col_name] = (var, nullable, col_type)
            ttk.Entry(frame, textvariable=var, width=40).pack(side="left", padx=5, fill="x", expand=True)
            
            # Type info
            ttk.Label(frame, text=f"({col_type})", foreground="gray", font=("", 8), width=15).pack(side="left", padx=2)
        
        # Scroll to top
        canvas.yview_moveto(0)
    
    combo_table.bind("<<ComboboxSelected>>", on_table_select)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # --- Nút tác vụ ---
    frame_buttons = ttk.Frame(dlg, padding=10)
    frame_buttons.pack(fill="x")
    
    def on_insert():
        table = combo_table.get()
        if not table:
            messagebox.showwarning("Lỗi", "Chọn bảng!")
            return
        
        # Lấy dữ liệu từ input (bỏ trống, kiểm tra bắt buộc)
        data = {}
        missing_required = []
        
        for col_name, (var, nullable, col_type) in input_vars.items():
            value = var.get().strip()
            
            if value:
                data[col_name] = value
            elif nullable == 'N':  # Bắt buộc phải có
                missing_required.append(col_name)
        
        # Kiểm tra các cột bắt buộc
        if missing_required:
            msg = f"Cột bắt buộc chưa nhập:\n" + "\n".join(f"  • {col}" for col in missing_required)
            messagebox.showwarning("Lỗi", msg)
            return
        
        if not data:
            messagebox.showwarning("Lỗi", "Nhập ít nhất một trường!")
            return
        
        # Insert via procedure
        success, msg = insert_record_via_proc(conn, table, data)
        
        if success:
            messagebox.showinfo("Thành công", msg)
            dlg.destroy()
        else:
            messagebox.showerror("Lỗi", msg)
    
    ttk.Button(frame_buttons, text="✅ Insert", command=on_insert).pack(side="left", padx=5)
    ttk.Button(frame_buttons, text="❌ Cancel", command=dlg.destroy).pack(side="left", padx=5)
    ttk.Label(frame_buttons, text="* = Bắt buộc", foreground="gray", font=("", 8)).pack(side="right")
    
    # Load bảng ban đầu
    on_table_select()
