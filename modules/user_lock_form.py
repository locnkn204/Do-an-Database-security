import tkinter as tk
from tkinter import ttk, messagebox


def open_lock_user_form(parent, conn):
    """
    Form khóa / mở khóa user Oracle.
    Yêu cầu quyền SYS hoặc ADMIN có ALTER USER.
    """
    win = tk.Toplevel(parent)
    win.title("Khóa / Mở khóa tài khoản Oracle")
    win.geometry("420x260")
    win.grab_set()

    ttk.Label(win, text="Tên user cần xử lý:", font=("Segoe UI", 11, "bold")).pack(pady=10)

    username = tk.StringVar()
    ttk.Entry(win, textvariable=username, width=35).pack()

    ttk.Label(win, text="Chọn tác vụ:", font=("Segoe UI", 11, "bold")).pack(pady=10)

    action = tk.StringVar(value="lock")
    ttk.Radiobutton(win, text="LOCK USER", variable=action, value="lock").pack()
    ttk.Radiobutton(win, text="UNLOCK USER", variable=action, value="unlock").pack()

    ttk.Separator(win).pack(fill="x", pady=12)

    def do_action():
        user = username.get().strip().upper()
        if not user:
            messagebox.showerror("Lỗi", "Bạn phải nhập tên user!")
            return

        try:
            cur = conn.cursor()
            if action.get() == "lock":
                cur.execute(f"ALTER USER {user} ACCOUNT LOCK")
                conn.commit()
                messagebox.showinfo("Thành công", f"User '{user}' đã bị KHÓA.")
            else:
                cur.execute(f"ALTER USER {user} ACCOUNT UNLOCK")
                conn.commit()
                messagebox.showinfo("Thành công", f"User '{user}' đã được MỞ KHÓA.")

            win.destroy()

        except Exception as e:
            messagebox.showerror("Lỗi SQL", str(e))

    ttk.Button(win, text="Thực thi", command=do_action).pack(pady=10)
    ttk.Button(win, text="Đóng", command=win.destroy).pack()
