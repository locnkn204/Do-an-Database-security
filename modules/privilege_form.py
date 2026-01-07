import tkinter as tk
from tkinter import ttk, messagebox

# ================== ORACLE ACTION ==================

def grant_priv(conn, user, table, priv):
    cur = conn.cursor()
    cur.callproc("grant_table_priv", [user, table, priv])
    conn.commit()
    cur.close()

def revoke_priv(conn, user, table, priv):
    cur = conn.cursor()
    cur.callproc("revoke_table_priv", [user, table, priv])
    conn.commit()
    cur.close()

# ================== TKINTER FORM ==================

def open_privilege_form(parent, conn):

    win = tk.Toplevel(parent)
    win.title("Gán / Thu hồi quyền người dùng")
    win.geometry("420x420")
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

    ttk.Label(win, text="Username").pack(anchor="w", padx=20)
    ttk.Entry(win, textvariable=v_user).pack(fill="x", padx=20, pady=5)

    ttk.Label(win, text="Table (vd: LOCB2.SINHVIEN)").pack(anchor="w", padx=20)
    ttk.Entry(win, textvariable=v_table).pack(fill="x", padx=20, pady=5)

    ttk.Label(win, text="Quyền").pack(anchor="w", padx=20, pady=(10, 0))
    for p, var in priv_vars.items():
        ttk.Checkbutton(win, text=p, variable=var).pack(anchor="w", padx=40)

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

