import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .encrypt_logic import run_encryption
from .crypto_rsa_oracle import oracle_rsa_generate_keypair


def open_encrypt_form(parent):

    win = tk.Toplevel(parent)
    win.title("Mã hóa / Giải mã tập tin")
    win.geometry("520x420")
    win.grab_set()

    algo = tk.StringVar(value="DES")
    action = tk.StringVar(value="encrypt")
    layer = tk.StringVar(value="app")  # "app" hoặc "db"
    src = tk.StringVar()
    dest = tk.StringVar()

    # ---------------- HEADER ----------------
    ttk.Label(win, text="Chọn thuật toán:", font=("Segoe UI", 11, "bold")).pack(pady=6)

    ttk.Combobox(
        win, textvariable=algo, state="readonly",
        values=["DES", "RSA", "ADDITIVE"]
    ).pack()

    ttk.Label(win, text="Tầng mã hóa:", font=("Segoe UI", 11, "bold")).pack(pady=6)
    
    layer_frame = ttk.Frame(win)
    layer_frame.pack()
    ttk.Radiobutton(layer_frame, text="🖥️ Tầng ứng dụng (Python)", variable=layer, value="app").pack(side="left", padx=10)
    ttk.Radiobutton(layer_frame, text="🗄️ Tầng database (Oracle)", variable=layer, value="db").pack(side="left", padx=10)

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
    
    key_hint = ttk.Label(win, text="", font=("Segoe UI", 8), foreground="blue")
    key_hint.pack()

    def update_key_hint(*args):
        if algo.get() == "RSA":
            if action.get() == "encrypt":
                key_hint.config(text="⚠️ Mã hóa: Dán PUBLIC KEY vào đây")
            else:
                key_hint.config(text="⚠️ Giải mã: Dán PRIVATE KEY vào đây")
        elif algo.get() == "ADDITIVE":
            key_hint.config(text="💡 Nhập số dịch chuyển (shift), ví dụ: 3, 7, 13... (mặc định = 3)")
        elif algo.get() == "DES":
            key_hint.config(text="💡 Nhập khóa DES (string), ví dụ: mysecret")
        else:
            key_hint.config(text="")
    
    algo.trace_add("write", update_key_hint)
    action.trace_add("write", update_key_hint)
    update_key_hint()

    key_box = tk.Text(win, height=4, width=50)
    key_box.pack()

    helper = ttk.Frame(win)
    helper.pack(pady=6)

    def gen_rsa_keys():
        """Tạo khóa RSA từ Oracle"""
        try:
            if not hasattr(parent, 'conn') or parent.conn is None:
                messagebox.showerror("Lỗi", "Cần kết nối database để tạo khóa!")
                return
            
            pub, priv = oracle_rsa_generate_keypair(parent.conn)
            key_box.delete("1.0", "end")
            key_box.insert("1.0", priv + "\n\n" + pub)
            messagebox.showinfo("✅ Tạo khóa thành công", 
                              "🔐 Khóa RSA đã được tạo từ Oracle\n\n"
                              "📋 PRIVATE KEY (dòng đầu) - dùng để GIẢI MÃ\n"
                              "📋 PUBLIC KEY (dòng cuối) - dùng để MÃ HÓA\n\n"
                              "⚠️ Copy từng key riêng biệt khi sử dụng!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo khóa:\n{e}")

    def gen_rsa_keys_oracle():
        """Tạo khóa RSA từ Oracle (alias)"""
        gen_rsa_keys()

    ttk.Button(helper, text="🔑 Tạo khóa RSA (1)", command=gen_rsa_keys).pack(side="left", padx=5)
    ttk.Button(helper, text="🗄️ Tạo khóa RSA (2)", command=gen_rsa_keys_oracle).pack(side="left", padx=5)

    ttk.Separator(win, orient="horizontal").pack(fill="x", pady=10)

    # ---------------- RUN ----------------
    def do_run():
    	try:
        	# Lấy username từ parent (đã đăng nhập)
        	current_username = getattr(parent, 'current_user', None)
        	
        	run_encryption(
            	algo.get(),
            	action.get(),
            	src.get(),
            	dest.get(),
            	key_box.get("1.0", "end").strip(),
            	conn=parent.conn,   # ✅ TRUYỀN ORACLE CONNECTION
            	layer=layer.get(),  # ✅ TRUYỀN TẦNG MÃ HÓA (app/db)
            	username=current_username  # ✅ TRUYỀN USERNAME ĐỂ GHI LOG
        	)
        	messagebox.showinfo("Success", f"{action.get().upper()} thành công!")
    	except Exception as e:
        	messagebox.showerror("Error", str(e))

    ttk.Button(
        win,
        text="Thực thi",
        command=do_run
    ).pack(pady=15)

