import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .encrypt_logic import run_encryption
from .crypto_des import des_generate_key
from .crypto_rsa import rsa_generate_keypair


def open_encrypt_form(parent):

    win = tk.Toplevel(parent)
    win.title("Mã hóa / Giải mã tập tin")
    win.geometry("520x420")
    win.grab_set()

    algo = tk.StringVar(value="DES")
    action = tk.StringVar(value="encrypt")
    src = tk.StringVar()
    dest = tk.StringVar()

    # ---------------- HEADER ----------------
    ttk.Label(win, text="Chọn thuật toán:", font=("Segoe UI", 11, "bold")).pack(pady=6)

    ttk.Combobox(
        win, textvariable=algo, state="readonly",
        values=["DES", "RSA"]
    ).pack()

    ttk.Label(win, text="Chế độ thực thi:", font=("Segoe UI", 11, "bold")).pack(pady=6)

    ttk.Combobox(
        win, textvariable=action, state="readonly",
        values=["encrypt", "decrypt"]
    ).pack()

    # ---------------- FILE SOURCE ----------------
    ttk.Label(win, text="File nguồn:", font=("Segoe UI", 11)).pack(pady=6)
    ttk.Entry(win, textvariable=src, width=45).pack()
    ttk.Button(win, text="Chọn file…", command=lambda: src.set(filedialog.askopenfilename())).pack()

    # ---------------- FILE DEST ----------------
    ttk.Label(win, text="File đích:", font=("Segoe UI", 11)).pack(pady=6)
    ttk.Entry(win, textvariable=dest, width=45).pack()
    ttk.Button(win, text="Lưu thành…", command=lambda: dest.set(filedialog.asksaveasfilename())).pack()

    # ---------------- KEY SECTION ----------------
    ttk.Label(win, text="Khóa / Public key / Private key:", font=("Segoe UI", 11, "bold")).pack(pady=8)

    key_box = tk.Text(win, height=4, width=50)
    key_box.pack()

    helper = ttk.Frame(win)
    helper.pack(pady=6)

    ttk.Button(helper, text="Tạo khóa DES",
               command=lambda: key_box.insert("1.0", des_generate_key().hex())
               ).pack(side="left", padx=5)

    def gen_rsa_keys():
        priv, pub = rsa_generate_keypair()
        key_box.delete("1.0", "end")
        key_box.insert("1.0", priv.decode() + "\n" + pub.decode())

    ttk.Button(helper, text="Tạo bộ RSA", command=gen_rsa_keys).pack(side="left", padx=5)

    ttk.Separator(win, orient="horizontal").pack(fill="x", pady=10)

    # ---------------- RUN ----------------
    def do_run():
        keytxt = key_box.get("1.0", "end").strip()
        try:
            run_encryption(algo.get(), action.get(), src.get(), dest.get(), keytxt)
            messagebox.showinfo("Thành công", f"{action.get().upper()} thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    ttk.Button(win, text="Thực thi", padding=10, command=do_run).pack(pady=10)
