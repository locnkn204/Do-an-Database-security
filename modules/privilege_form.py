import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Import hàm chuyển đổi username từ doantuan9
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
try:
    from doantuan9 import build_oracle_username
except ImportError:
    build_oracle_username = None

# ================== ORACLE ACTION ==================

def grant_priv(conn, user, table, priv):
    cur = conn.cursor()
    
    # Chuyển đổi username nếu cần (app username -> oracle username)
    oracle_user = user.upper()
    if build_oracle_username and not oracle_user.startswith('U_'):
        # Nếu user không phải admin và không có prefix U_ → chuyển đổi
        if oracle_user not in ('SYS', 'SYSTEM', 'LOCB2', 'ADMIN', 'PUBLIC'):
            try:
                oracle_user = build_oracle_username(user)
                print(f"🔄 Chuyển đổi username: {user} → {oracle_user}")
            except Exception:
                pass  # Giữ nguyên nếu lỗi
    
    cur.callproc("grant_table_priv", [oracle_user, table, priv])
    
    # Nếu cấp INSERT → tự động cấp EXECUTE trên procedure insert_record_generic
    if priv.upper() == "INSERT":
        try:
            cur.execute(f"GRANT EXECUTE ON LOCB2.insert_record_generic TO {oracle_user}")
            print(f"✅ Đã tự động cấp EXECUTE ON insert_record_generic cho {oracle_user}")
        except Exception as e:
            print(f"⚠️ Không thể cấp EXECUTE ON insert_record_generic: {e}")
    
    conn.commit()
    cur.close()

def revoke_priv(conn, user, table, priv):
    cur = conn.cursor()
    
    # Chuyển đổi username nếu cần (app username -> oracle username)
    oracle_user = user.upper()
    if build_oracle_username and not oracle_user.startswith('U_'):
        # Nếu user không phải admin và không có prefix U_ → chuyển đổi
        if oracle_user not in ('SYS', 'SYSTEM', 'LOCB2', 'ADMIN', 'PUBLIC'):
            try:
                oracle_user = build_oracle_username(user)
                print(f"🔄 Chuyển đổi username: {user} → {oracle_user}")
            except Exception:
                pass  # Giữ nguyên nếu lỗi
    
    cur.callproc("revoke_table_priv", [oracle_user, table, priv])
    
    # Nếu thu hồi INSERT → tự động thu hồi EXECUTE trên procedure insert_record_generic
    if priv.upper() == "INSERT":
        try:
            cur.execute(f"REVOKE EXECUTE ON LOCB2.insert_record_generic FROM {oracle_user}")
            print(f"✅ Đã tự động thu hồi EXECUTE ON insert_record_generic từ {oracle_user}")
        except Exception as e:
            print(f"⚠️ Không thể thu hồi EXECUTE ON insert_record_generic: {e}")
    
    conn.commit()
    cur.close()

# ================== TKINTER FORM ==================

def open_privilege_form(parent, conn):

    win = tk.Toplevel(parent)
    win.title("Gán / Thu hồi quyền người dùng")
    win.geometry("480x480")
    win.grab_set()

    # ---------- VARIABLES ----------
    v_user = tk.StringVar()
    v_table = tk.StringVar()
    v_action = tk.StringVar(value="GRANT")

    priv_vars = {
        "SELECT": tk.BooleanVar(),
        "INSERT": tk.BooleanVar(),
        "UPDATE": tk.BooleanVar(),
        "DELETE": tk.BooleanVar()
    }

    # ---------- UI ----------
    ttk.Label(win, text="QUẢN LÝ QUYỀN USER", font=("Segoe UI", 14, "bold")).pack(pady=10)

    ttk.Label(win, text="Username (vd: locb3, hoặc U_xxx nếu biết)").pack(anchor="w", padx=20)
    ttk.Entry(win, textvariable=v_user).pack(fill="x", padx=20, pady=5)
    
    # Hint cho username
    hint = ttk.Label(win, text="💡 Nhập app username (locb3), hệ thống tự chuyển sang oracle username", 
                    font=("Segoe UI", 8), foreground="blue")
    hint.pack(anchor="w", padx=20)

    ttk.Label(win, text="Table (vd: LOCB2.USERS)").pack(anchor="w", padx=20, pady=(5,0))
    ttk.Entry(win, textvariable=v_table).pack(fill="x", padx=20, pady=5)

    ttk.Label(win, text="Quyền").pack(anchor="w", padx=20, pady=(10, 0))
    for p, var in priv_vars.items():
        ttk.Checkbutton(win, text=p, variable=var).pack(anchor="w", padx=40)
    
    # Hint cho INSERT privilege
    insert_hint = ttk.Label(win, text="⚠️ INSERT tự động cấp quyền gọi procedure add_data", 
                           font=("Segoe UI", 8), foreground="green")
    insert_hint.pack(anchor="w", padx=40)

    ttk.Label(win, text="Hành động").pack(anchor="w", padx=20, pady=(10, 0))
    ttk.Radiobutton(win, text="Gán quyền (GRANT)", value="GRANT", variable=v_action).pack(anchor="w", padx=40)
    ttk.Radiobutton(win, text="Thu hồi quyền (REVOKE)", value="REVOKE", variable=v_action).pack(anchor="w", padx=40)

    # ---------- ACTION ----------
    def execute():
        user = v_user.get().strip().upper()
        table = v_table.get().strip().upper()

        if not user or not table:
            messagebox.showwarning("Thiếu thông tin", "Nhập user và table")
            return

        selected_privs = [p for p, v in priv_vars.items() if v.get()]
        if not selected_privs:
            messagebox.showwarning("Thiếu quyền", "Chọn ít nhất 1 quyền")
            return

        try:
            for priv in selected_privs:
                if v_action.get() == "GRANT":
                    grant_priv(conn, user, table, priv)
                else:
                    revoke_priv(conn, user, table, priv)

            messagebox.showinfo(
                "Thành công",
                f"{v_action.get()} quyền thành công cho {user}"
            )

        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    ttk.Button(win, text="Thực thi", command=execute).pack(pady=20)
    ttk.Button(win, text="Đóng", command=win.destroy).pack()

