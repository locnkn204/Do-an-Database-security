import tkinter as tk
from tkinter import ttk, messagebox

def open_delete_user_form(parent, conn):
    """
    Form xóa user Oracle — yêu cầu kết nối bằng SYS as SYSDBA
    """
    win = tk.Toplevel(parent)
    win.title("Xóa người dùng Oracle")
    win.geometry("420x260")
    win.grab_set()

    ttk.Label(win, text="Nhập tên user cần xóa:", font=("Segoe UI", 11, "bold")).pack(pady=10)

    username = tk.StringVar()
    ttk.Entry(win, textvariable=username, width=35).pack()

    ttk.Label(win, text="Tùy chọn:", font=("Segoe UI", 11, "bold")).pack(pady=10)

    drop_type = tk.StringVar(value="cascade")
    ttk.Radiobutton(win, text="DROP USER <name> CASCADE", variable=drop_type,
                    value="cascade").pack()
    ttk.Radiobutton(win, text="DROP USER <name>", variable=drop_type,
                    value="normal").pack()

    ttk.Separator(win).pack(fill="x", pady=12)

    def do_delete():
        user = username.get().strip().upper()
        if not user:
            messagebox.showerror("Lỗi", "Bạn phải nhập tên user!")
            return
        try:
            cur = conn.cursor()
            if drop_type.get() == "cascade":
                cur.execute(f"DROP USER {user} CASCADE")
            else:
                cur.execute(f"DROP USER {user}")
            conn.commit()
            messagebox.showinfo("Thành công", f"User '{user}' đã bị xóa.")
            win.destroy()
        except Exception as e:
            messagebox.showerror("Lỗi khi xóa user", str(e))

    ttk.Button(win, text="Xóa user", command=do_delete).pack(pady=10)
    ttk.Button(win, text="Đóng", command=win.destroy).pack()