import tkinter as tk
from tkinter import ttk, messagebox
import base64
import hashlib
from datetime import datetime
import threading
import time

from modules.privilege_form import open_privilege_form
from modules.encrypt_logic import run_encryption
from modules.crypto_rsa import rsa_generate_keypair
from modules.user_tools import delete_user
from modules.encrypt_form import open_encrypt_form
from modules.user_delete_form import open_delete_user_form
from modules.user_lock_form import open_lock_user_form
from modules.user_viewer_form import open_user_viewer_form

# Import ứng dụng ký số
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Kyso'))
try:
    from appkyso import DigitalSignatureApp
except ImportError:
    DigitalSignatureApp = None

# oracledb import
try:
    import oracledb
except Exception as e:
    oracledb = None

def listen_logout(conn, app_ref, username):
    """Lắng nghe logout alert riêng cho từng user."""
    cur = None
    # Tạo alert name riêng cho user này
    alert_name = f'LOGOUT_ALERT_{username.upper()}'
    
    try:
        cur = conn.cursor()
        cur.callproc('DBMS_ALERT.REGISTER', [alert_name])
        # vòng chờ ngắn để phản hồi nhanh (2s thay vì 10s)
        while not app_ref._stop_listener:
            try:
                channel, message, status, timeout = cur.callproc(
                    'DBMS_ALERT.WAITONE',
                    [alert_name, '', 0, 2]
                )
            except Exception:
                break

            # nếu chính phiên này đang tự logout -> dừng listener
            if app_ref._is_local_logout:
                break

            if message == 'LOGOUT_NOW':
                # TẤT CẢ thao tác UI phải đưa về main thread (Tkinter không thread-safe)
                def _do_ui_logout():
                    try:
                        if app_ref.conn:
                            app_ref.conn.close()
                    except Exception:
                        pass
                    app_ref.conn = None
                    app_ref.current_user = None
                    app_ref._stop_listener = True
                    app_ref._build_login_frame()
                    messagebox.showwarning("Session ended",
                                           "Bị đăng xuất do phiên khác logout.")
                try:
                    app_ref.after(0, _do_ui_logout)
                except Exception:
                    _do_ui_logout()
                break
    finally:
        try:
            if cur:
                try:
                    cur.callproc('DBMS_ALERT.UNREGISTER', [alert_name])
                except Exception:
                    pass
                cur.close()
        except Exception:
            pass


def logout_all_other_sessions(conn, current_username, exclude_sid=None):
    """
    Ngắt kết nối TẤT CẢ các phiên của user, trừ phiên hiện tại.
    
    Args:
        conn: Kết nối Oracle hiện tại
        current_username: Username cần logout (ví dụ: 'LOCB3')
        exclude_sid: SID của phiên hiện tại (để không kill chính mình)
    
    Returns:
        int: Số phiên đã logout
    """
    try:
        cur = conn.cursor()
        
        # Tạo alert name riêng cho user này
        alert_name = f'LOGOUT_ALERT_{current_username.upper()}'
        
        # Lấy SID của phiên hiện tại nếu chưa có
        if exclude_sid is None:
            cur.execute("""
                SELECT sid 
                FROM v$session 
                WHERE audsid = SYS_CONTEXT('USERENV', 'SESSIONID')
            """)
            result = cur.fetchone()
            exclude_sid = result[0] if result else None
        
        # Lấy danh sách TẤT CẢ phiên của user (trừ phiên hiện tại)
        if exclude_sid:
            cur.execute("""
                SELECT sid, serial#, machine, program
                FROM v$session
                WHERE username = :uname
                  AND sid != :exclude_sid
                  AND type = 'USER'
            """, {'uname': current_username.upper(), 'exclude_sid': exclude_sid})
        else:
            cur.execute("""
                SELECT sid, serial#, machine, program
                FROM v$session
                WHERE username = :uname
                  AND type = 'USER'
            """, {'uname': current_username.upper()})
        
        sessions_to_kill = cur.fetchall()
        
        if not sessions_to_kill:
            print(f"✅ Không có phiên nào khác của {current_username}")
            return 0
        
        # Gửi SIGNAL riêng cho user này (không ảnh hưởng users khác)
        try:
            cur.callproc('DBMS_ALERT.SIGNAL', [alert_name, 'LOGOUT_NOW'])
            conn.commit()
            print(f"📤 Đã gửi DBMS_ALERT đến {len(sessions_to_kill)} phiên của {current_username}")
        except Exception as e:
            print(f"⚠️ Không thể gửi DBMS_ALERT: {e}")
        
        # Đợi 1s để DBMS_ALERT được xử lý (graceful logout)
        time.sleep(1)
        
        # Kill các phiên còn lại (nếu chưa logout)
        killed_count = 0
        for sid, serial, machine, program in sessions_to_kill:
            try:
                # Kiểm tra phiên còn tồn tại không
                cur.execute("""
                    SELECT COUNT(*) 
                    FROM v$session 
                    WHERE sid = :sid AND serial# = :serial
                """, {'sid': sid, 'serial': serial})
                
                if cur.fetchone()[0] == 0:
                    print(f"✅ Phiên SID={sid} đã logout (qua DBMS_ALERT)")
                    continue
                
                # Kill session
                cur.execute(f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE")
                killed_count += 1
                print(f"🔴 Đã kill phiên: SID={sid}, Serial={serial}, Device={machine}")
                
            except oracledb.DatabaseError as e:
                error_code = e.args[0].code if e.args else None
                if error_code == 30:  # ORA-00030: Session không tồn tại
                    print(f"✅ Phiên SID={sid} đã không còn tồn tại")
                elif error_code == 31:  # ORA-00031: Session đang được marked for kill
                    print(f"⏳ Phiên SID={sid} đang được kill")
                    killed_count += 1
                else:
                    print(f"❌ Lỗi kill phiên SID={sid}: {e}")
        
        conn.commit()
        total_affected = len(sessions_to_kill)
        print(f"✅ Đã logout {total_affected} phiên khác của {current_username}")
        return total_affected
        
    except Exception as e:
        print(f"❌ Lỗi trong logout_all_other_sessions: {e}")
        return 0


def check_session_limit(conn, username, max_sessions=1):
    """
    Kiểm tra số phiên đang kết nối của user.
    
    Args:
        conn: Kết nối Oracle
        username: Username cần check
        max_sessions: Giới hạn số phiên (mặc định = 1)
    
    Returns:
        tuple: (current_count, exceeded) - số phiên hiện tại và có vượt quá không
    """
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*)
            FROM v$session
            WHERE username = :uname
              AND type = 'USER'
        """, {'uname': username.upper()})
        
        count = cur.fetchone()[0]
        exceeded = count > max_sessions
        
        return count, exceeded
        
    except Exception as e:
        print(f"❌ Lỗi kiểm tra session limit: {e}")
        return 0, False


# --------------------- Application-level "encryption" ---------------------
def _encrypt_file_ui(self):
    # Hàm UI để gọi run_encryption
    algo = "des"          # hoặc "rsa", "aes"
    action = "encrypt"    # hoặc "decrypt"
    src = "input.txt"     # đường dẫn file nguồn
    dest = "output.enc"   # đường dẫn file đích
    keytxt = "mysecretkey"

    try:
        run_encryption(algo, action, src, dest, keytxt)
        messagebox.showinfo("Success", f"File đã được {action} thành công!")
    except Exception as e:
        messagebox.showerror("Error", f"Lỗi khi {action} file:\n{e}")

def open_digital_signature_app(parent):
    """Mở ứng dụng ký số trong cửa sổ mới"""
    if DigitalSignatureApp is None:
        messagebox.showerror("Lỗi", 
            "Không thể tải ứng dụng ký số!\n\n"
            "Kiểm tra lại:\n"
            "- File appkyso.py có tồn tại trong thư mục Kyso không\n"
            "- Thư viện cryptography đã được cài đặt chưa: pip install cryptography")
        return
    
    try:
        # Tạo cửa sổ mới cho ứng dụng ký số
        kyso_window = tk.Toplevel(parent)
        kyso_window.withdraw()  # Ẩn cửa sổ tạm thời
        
        # Khởi tạo ứng dụng ký số với cửa sổ mới
        app = DigitalSignatureApp(kyso_window)
        
        # Hiển thị cửa sổ
        kyso_window.deiconify()
        
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể mở ứng dụng ký số:\n{e}")

def simple_encrypt(pw: str, add: int = 7, mul: int = 3, length: int = 60) -> str:
    if pw is None:
        pw = ""
    b = bytearray()
    for ch in pw:
        val = ((ord(ch) + add) * mul) & 0xFF
        b.append(val)
    enc = base64.b64encode(bytes(b)).decode("ascii")
    if len(enc) < length:
        times = (length // len(enc)) + 1 if len(enc) > 0 else 1
        enc = (enc * times)[:length]
    else:
        enc = enc[:length]
    return enc

# ====== APP-LEVEL ADDITIVE ENCRYPTION (CHAR MODE) + ORACLE-SAFE USERNAME ======
K_DEMO = 37  # KHÓA CỘNG CỐ ĐỊNH CHO DEMO — không đổi sau khi đã tạo user

def assert_ascii_only(s: str):
	"""Chỉ chấp nhận ASCII (không dấu/emoji)."""
	try:
		s.encode("ascii")
	except UnicodeEncodeError:
		raise ValueError("Chỉ cho phép ký tự ASCII (không dấu/emoji).")

def enc_add_char(s: str, k: int = K_DEMO) -> str:
	"""
	Mã hóa cộng theo ký tự (demo):
	  out[i] = chr( (ord(s[i]) + k) mod 256 )
	"""
	assert_ascii_only(s)
	k &= 0xFF
	return "".join(chr((ord(ch) + k) & 0xFF) for ch in s)

def _to_base32_no_pad_upper(raw_bytes: bytes) -> str:
	"""Base32 UPPER và bỏ dấu '=' padding (Oracle-safe: A–Z, 2–7)."""
	return base64.b32encode(raw_bytes).decode("ascii").rstrip("=").upper()

def build_oracle_username(app_username: str) -> str:
	"""
	U′ = 'U_' + Base32( enc_add_char(username).encode('latin-1') ), cắt ≤ 30.
	-> Oracle-safe: chỉ A–Z, 2–7 và '_', KHÔNG cần quoted identifier.
	"""
	enc = enc_add_char(app_username)
	b32 = _to_base32_no_pad_upper(enc.encode("latin-1", errors="strict"))
	uname = f"U_{b32}"
	# Giữ ≤ 30 ký tự để tương thích rộng rãi
	if len(uname) > 30:
		uname = uname[:30]
	return uname

def build_oracle_password(app_password: str) -> str:
    """
    Ptmp = enc_add_char(password)
    H    = SHA256(Ptmp).hexdigest()  # 64 hex
    P'   = rút gọn để tương thích Oracle cũ (≤ 30 ký tự).
    Nếu DB bật policy phức tạp, thêm 'Aa!' cho đủ loại ký tự (tổng = 30).
    """
    enc = enc_add_char(app_password)
    h = hashlib.sha256(enc.encode("latin-1", errors="strict")).hexdigest()  # 64 hex
    # Giữ tương thích tối đa: 30 ký tự
    base = h[:27]            # 27 hex đầu
    pw = base + "Aa!"        # thêm để qua policy (hoa/thường/đặc biệt) => 30 ký tự
    return pw


def build_oracle_credentials(app_username: str, app_password: str):
	"""Trả về (U′, P′) để dùng cho CREATE USER / đăng nhập."""
	return build_oracle_username(app_username), build_oracle_password(app_password)

# ------------------------- Oracle helpers --------------------------------
def make_connection(user, password, host, port, sid, use_sysdba=False):
    if oracledb is None:
        raise RuntimeError("The 'oracledb' package is not installed. Install with: pip install oracledb")
    dsn = oracledb.makedsn(host, int(port), sid=sid)
    if user.strip().lower() == "sys" or use_sysdba:
        return oracledb.connect(user=user, password=password, dsn=dsn, mode=oracledb.AUTH_MODE_SYSDBA)
    return oracledb.connect(user=user, password=password, dsn=dsn)

# tạo user mới và grant toàn bộ bảng của LOCB2
def create_user_and_grant(conn, new_user, new_password,
                          grant_schema_owner="LOCB2",
                          default_tbs="USERS", temp_tbs="TEMP", quota_mb=100):
    new_user_u = new_user.upper()
    owner_u = grant_schema_owner.upper()
    cur = conn.cursor()

    # 1️Tạo user
    cur.execute(f'CREATE USER {new_user_u} IDENTIFIED BY "{new_password}" '
                f'DEFAULT TABLESPACE {default_tbs} TEMPORARY TABLESPACE {temp_tbs}')
    cur.execute(f"ALTER USER {new_user_u} QUOTA {quota_mb}M ON {default_tbs}")

    # 2Quyền đăng nhập
    try:
        cur.execute(f"GRANT CREATE SESSION TO {new_user_u}")
    except Exception:
        cur.execute(f"GRANT CONNECT TO {new_user_u}")

    # <-- added: grant EXECUTE on SYS.DBMS_ALERT so app can SIGNAL/WAIT if needed
    try:
        cur.execute(f'GRANT EXECUTE ON SYS.DBMS_ALERT TO {new_user_u}')
    except Exception as e:
        # non-fatal, log for troubleshooting
        print(f"⚠️ Không thể cấp EXECUTE trên SYS.DBMS_ALERT cho {new_user_u}: {e}")

    # 3️ Cấp quyền SELECT toàn bộ bảng của LOCB2
    cur.execute("SELECT table_name FROM all_tables WHERE owner = :own", {"own": owner_u})
    tables = [r[0] for r in cur.fetchall()]

    for t in tables:
        try:
            cur.execute(f"GRANT SELECT ON {owner_u}.{t} TO {new_user_u}")
        except Exception as e:
            print(f"⚠️ Không thể cấp quyền cho {t}: {e}")

    conn.commit()
    return tables

# hiển thị cả bảng sở hữu và bảng được cấp quyền SELECT
def list_user_tables(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name FROM user_tables
        UNION
        SELECT table_name
        FROM all_tab_privs
        WHERE grantee = USER
          AND privilege = 'SELECT'
        ORDER BY table_name
    """)
    tables = [r[0] for r in cur.fetchall()]
    return tables

def fetch_table_preview(conn, table_name, limit=200):
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT * FROM {table_name} WHERE ROWNUM < 1")
        schema_prefix = ""
    except oracledb.DatabaseError:
        schema_prefix = "LOCB2."
        cur.execute(f"SELECT * FROM {schema_prefix}{table_name} WHERE ROWNUM < 1")

    col_names = [d[0] for d in cur.description]
    cur.execute(f"SELECT * FROM {schema_prefix}{table_name} FETCH FIRST {int(limit)} ROWS ONLY")
    rows = cur.fetchall()
    return col_names, rows

# ------------------------------- UI --------------------------------------
class OracleApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Oracle Tkinter Demo — Login | Register | View Tables")
        self.geometry("980x620")
        self.resizable(True, True)

        self.conn = None
        self.current_user = None
        self._stop_listener = False       # yêu cầu thread dừng
        self._is_local_logout = False     # phiên này logout
        self.max_sessions = 2              # Giới hạn số phiên đồng thời (thay đổi thành 2, 3... nếu cần)

        self._build_login_frame()
    
    # ---------- Frames ----------
    def _build_login_frame(self):
        self._clear_frames()
        f = ttk.Frame(self, padding=20)
        f.pack(fill="both", expand=True)

        ttk.Label(f, text="Oracle Connection", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=4, pady=(0, 15))

        ttk.Label(f, text="Host").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.var_host = tk.StringVar(value="localhost")
        ttk.Entry(f, textvariable=self.var_host, width=25).grid(row=1, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="Port").grid(row=1, column=2, sticky="e", padx=5, pady=5)
        self.var_port = tk.StringVar(value="1521")
        ttk.Entry(f, textvariable=self.var_port, width=10).grid(row=1, column=3, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="SID").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.var_sid = tk.StringVar(value="orcl")
        ttk.Entry(f, textvariable=self.var_sid, width=25).grid(row=2, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="Username").grid(row=3, column=0, sticky="e", padx=5, pady=5)
        self.var_user = tk.StringVar(value="locb3")
        ttk.Entry(f, textvariable=self.var_user, width=25).grid(row=3, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="Password").grid(row=3, column=2, sticky="e", padx=5, pady=5)
        self.var_pw = tk.StringVar(value="locb2")
        ttk.Entry(f, textvariable=self.var_pw, width=25, show="*").grid(row=3, column=3, sticky="w", padx=5, pady=5)

        self.var_sysdba = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Connect as SYSDBA (use for SYS)", variable=self.var_sysdba).grid(row=4, column=1, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Button(f, text="Login", command=self._login).grid(row=5, column=1, sticky="w", padx=5, pady=20)
        ttk.Button(f, text="Register (create Oracle user)", command=self._open_register_dialog).grid(row=5, column=2, sticky="w", padx=5, pady=20)

        ttk.Separator(f, orient="horizontal").grid(row=6, column=0, columnspan=4, sticky="ew", pady=(10, 10))
        info = ("Tips:\n"
                "- Default DSN: localhost:1521 (SID=orcl)\n"
                "- Login with 'locb2/locb2' to view tables in schema LOCB2.\n"
                "- To register a new Oracle user, your logged-in account must have privileges (e.g., SYS as SYSDBA).")
        ttk.Label(f, text=info, justify="left").grid(row=7, column=0, columnspan=4, sticky="w", padx=5)

    def _build_main_frame(self):
        self._clear_frames()
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=f"Connected as: {self.current_user}", font=("Segoe UI", 12, "bold")).pack(side="left")
        ttk.Button(top, text="Register new user", command=self._open_register_dialog).pack(side="left", padx=10)
        ttk.Button(top, text="Logout", command=self._logout).pack(side="right")

        # --- Thanh nút chức năng sau khi đăng nhập ---
        actions = ttk.Frame(self, padding=(10, 0))
        actions.pack(fill="x")

        ttk.Button(actions, text="Load data", command=self._show_load_data_form).pack(side="left", padx=6)
        ttk.Button(actions, text="Add data", command=lambda: messagebox.showinfo("Coming soon", "Tính năng Add data sẽ có sau.")).pack(side="left", padx=6)
        ttk.Button(actions, text="Mã hóa tập tin", command=lambda: open_encrypt_form(self)).pack(side="left", padx=6)
        ttk.Button(actions, text="Ký số", command=lambda: open_digital_signature_app(self)).pack(side="left", padx=6)
        ttk.Button(actions, text="Quản lý user", command=lambda: self._open_user_viewer_if_admin()).pack(side="left", padx=6)
        ttk.Button(actions, text="Phân quyền user",
           command=lambda: open_privilege_form(self, self.conn)
           ).pack(side="left", padx=6)

        ttk.Button(actions, text="Khóa/Mở user", command=lambda: open_lock_user_form(self, self.conn)).pack(side="left", padx=6)
	
        mid = ttk.Frame(self, padding=10)
        mid.pack(fill="x")
        ttk.Label(mid, text="Choose table:").pack(side="left")
        self.combo_tables = ttk.Combobox(mid, state="readonly", width=40)
        self.combo_tables.pack(side="left", padx=8)
        ttk.Button(mid, text="Load data", command=self._load_selected_table).pack(side="left", padx=8)

        self.tree = ttk.Treeview(self, show="headings")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        try:
            tables = list_user_tables(self.conn)
            if not tables:
                messagebox.showinfo("No tables", "This schema has no user tables or granted tables.")
            self.combo_tables["values"] = tables
            if tables:
                self.combo_tables.current(0)
        except Exception as e:
            messagebox.showerror("Error listing tables", str(e))

    def _clear_frames(self):
        for w in self.winfo_children():
            w.destroy()

    def _login(self):
        host = self.var_host.get().strip()
        port = self.var_port.get().strip()
        sid  = self.var_sid.get().strip()
        user = self.var_user.get().strip()
        pw   = self.var_pw.get()

        try:
            # Thêm 'admin' vào danh sách tài khoản đặc biệt không mã hóa
            if user.lower() in ("sys", "locb2", "admin","huyen") or self.var_sysdba.get():
                oracle_user, oracle_pw = user, pw
            else:
                try:
                    oracle_user, oracle_pw = build_oracle_credentials(user, pw)
                except ValueError as ve:
                    messagebox.showerror("Invalid characters", str(ve))
                    return

            conn = make_connection(oracle_user, oracle_pw, host, port, sid, use_sysdba=self.var_sysdba.get())
        except oracledb.DatabaseError as e:
            error, = e.args
            if error.code == 1017:  # ORA-01017: invalid username/password
                messagebox.showerror("Đăng nhập thất bại", 
                    "Sai tên đăng nhập hoặc mật khẩu!\n\n"
                    "Lưu ý:\n"
                    "- Kiểm tra lại tài khoản và mật khẩu\n"
                    "- Phân biệt chữ hoa/thường\n"
                    "- Với tài khoản SYS cần tick chọn SYSDBA")
            elif error.code == 12170:  # TNS:Connect timeout
                messagebox.showerror("Lỗi kết nối", 
                    "Không thể kết nối đến máy chủ Oracle!\n\n"
                    "Kiểm tra lại:\n"
                    "- Địa chỉ host và port\n" 
                    "- Oracle có đang chạy không?\n"
                    "- Tường lửa có chặn không?")
            elif error.code == 12514:  # TNS:listener does not currently know of service
                messagebox.showerror("Lỗi cấu hình",
                    f"Không tìm thấy SID '{sid}' trên máy chủ!\n\n"
                    "Kiểm tra lại tên SID có đúng không.")
            else:
                messagebox.showerror("Lỗi kết nối", 
                    f"Không thể kết nối:\n{str(e)}\n\n"
                    f"Mã lỗi Oracle: {error.code}")
            return
        except Exception as e:
            messagebox.showerror("Lỗi kết nối", 
                f"Lỗi không xác định:\n{str(e)}")
            return

        # Kiểm tra session limit và logout các phiên khác nếu cần
        try:
            current_count, exceeded = check_session_limit(conn, oracle_user, self.max_sessions)
            
            if exceeded:
                # Có quá nhiều phiên → logout các phiên khác
                print(f"⚠️ Phát hiện {current_count} phiên (giới hạn: {self.max_sessions})")
                
                affected = logout_all_other_sessions(conn, oracle_user)
                
                if affected > 0:
                    messagebox.showinfo("Đăng nhập",
                        f"Đã đăng xuất {affected} thiết bị khác.\n"
                        f"Giới hạn: {self.max_sessions} thiết bị cùng lúc.")
        except Exception as e:
            print(f"⚠️ Không thể kiểm tra session limit: {e}")

        # Reset flags trước khi start listener (fix bug logout lần 2)
        self._stop_listener = False       # Cho phép listener hoạt động
        self._is_local_logout = False     # Reset trạng thái logout
        
        self.conn = conn
        self.current_user = user
        messagebox.showinfo("Login success", f"Đăng nhập thành công đến {host}:{port}/{sid} as {user}")
        self._build_main_frame()
        # Truyền username để tạo alert name riêng cho user này
        threading.Thread(target=listen_logout, args=(self.conn, self, oracle_user), daemon=True).start()


    def _logout(self):
        try:
            if self.conn:
                self._is_local_logout = True     # đánh dấu là logout cục bộ
                self._stop_listener = True       # yêu cầu thread dừng

                # Logout tất cả phiên khác trước
                try:
                    affected = logout_all_other_sessions(self.conn, self.current_user)
                    if affected > 0:
                        print(f"✅ Đã logout {affected} phiên khác trước khi thoát")
                except Exception as e:
                    print(f"⚠️ Không thể logout các phiên khác: {e}")

                # Tạo alert name riêng cho user này
                cur = self.conn.cursor()
                cur.execute("SELECT USER FROM DUAL")
                oracle_username = cur.fetchone()[0].upper()
                alert_name = f'LOGOUT_ALERT_{oracle_username}'
                
                # Ngừng đăng ký kênh lắng nghe 
                try:
                    cur.callproc('DBMS_ALERT.UNREGISTER', [alert_name])
                except Exception:
                    pass

                # Phát tín hiệu cho các phiên còn lại (nếu có)
                try:
                    cur.callproc('DBMS_ALERT.SIGNAL', [alert_name, 'LOGOUT_NOW'])
                    self.conn.commit()
                except Exception:
                    pass

                # Thông báo riêng cho thiết bị hiện tại rồi đóng kết nối ngay
                messagebox.showinfo("Đăng xuất", "Bạn đã đăng xuất khỏi tất cả các thiết bị.")
                self.conn.close()
        except Exception:
            pass
        self.conn = None
        self.current_user = None
        self._build_login_frame()

    def _open_user_viewer_if_admin(self):
        """Mở form quản lý user chỉ khi có quyền admin"""
        if not self.conn:
            messagebox.showerror("Lỗi", "Không có kết nối database!")
            return
        
        try:
            # Kiểm tra quyền admin
            cur = self.conn.cursor()
            cur.execute("SELECT USER FROM DUAL")
            current_user = cur.fetchone()[0].upper()
            
            # Nếu là LOCB2, SYS, SYSTEM -> cho phép
            if current_user in ('LOCB2', 'SYS', 'SYSTEM'):
                open_user_viewer_form(self, self.conn)
                return
            
            # Kiểm tra có role DBA không
            cur.execute("""
                SELECT COUNT(*) 
                FROM USER_ROLE_PRIVS 
                WHERE GRANTED_ROLE = 'DBA'
            """)
            has_dba = cur.fetchone()[0] > 0
            
            if has_dba:
                open_user_viewer_form(self, self.conn)
            else:
                messagebox.showerror("Từ Chối Truy Cập",
                    f"Chức năng này chỉ dành cho quản trị viên!\n\n"
                    f"Người dùng hiện tại: {current_user}\n"
                    f"Cần có quyền DBA hoặc là tài khoản LOCB2/SYS.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể kiểm tra quyền:\n{e}")

    def _open_register_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Register New Oracle User")
        dlg.geometry("520x380")
        dlg.transient(self)
        dlg.grab_set()

        pad = 8
        ttk.Label(dlg, text="Create Oracle User (requires admin privileges)", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=(10, 10))
        ttk.Label(dlg, text="New username").grid(row=1, column=0, sticky="e", padx=pad, pady=pad)
        v_user = tk.StringVar()
        ttk.Entry(dlg, textvariable=v_user, width=28).grid(row=1, column=1, sticky="w", padx=pad, pady=pad)

        ttk.Label(dlg, text="New password").grid(row=2, column=0, sticky="e", padx=pad, pady=pad)
        v_pw = tk.StringVar()
        ttk.Entry(dlg, textvariable=v_pw, show="*", width=28).grid(row=2, column=1, sticky="w", padx=pad, pady=pad)

        ttk.Label(dlg, text="Grant read on schema").grid(row=3, column=0, sticky="e", padx=pad, pady=pad)
        v_schema = tk.StringVar(value="LOCB2")
        ttk.Entry(dlg, textvariable=v_schema, width=28).grid(row=3, column=1, sticky="w", padx=pad, pady=pad)

        ttk.Label(dlg, text="Default tablespace").grid(row=4, column=0, sticky="e", padx=pad, pady=pad)
        v_def_tbs = tk.StringVar(value="USERS")
        ttk.Entry(dlg, textvariable=v_def_tbs, width=28).grid(row=4, column=1, sticky="w", padx=pad, pady=pad)

        ttk.Label(dlg, text="Temp tablespace").grid(row=5, column=0, sticky="e", padx=pad, pady=pad)
        v_tmp_tbs = tk.StringVar(value="TEMP")
        ttk.Entry(dlg, textvariable=v_tmp_tbs, width=28).grid(row=5, column=1, sticky="w", padx=pad, pady=pad)

        ttk.Label(dlg, text="Quota (MB)").grid(row=6, column=0, sticky="e", padx=pad, pady=pad)
        v_quota = tk.IntVar(value=100)
        ttk.Entry(dlg, textvariable=v_quota, width=28).grid(row=6, column=1, sticky="w", padx=pad, pady=pad)

        def on_create():
            if self.conn is None:
                messagebox.showerror("Not connected", "Login first as SYS (with SYSDBA).")
                return
            new_user = v_user.get().strip()
            new_pw   = v_pw.get()
            if not new_user or not new_pw:
                messagebox.showwarning("Missing data", "Username and password are required.")
                return
            try:
                # Xử lý tài khoản đặc biệt (SYS, LOCB2)
                if new_user.lower() in ("sys", "locb2", "admin"):
                    oracle_uname, oracle_pw = new_user, new_pw
                else:
                    try:
                        oracle_uname, oracle_pw = build_oracle_credentials(new_user, new_pw)
                    except ValueError as ve:
                        messagebox.showerror("Invalid characters", str(ve))
                        return

                tables = create_user_and_grant(self.conn, oracle_uname, oracle_pw,
                                               grant_schema_owner=v_schema.get().strip() or "LOCB2",
                                               default_tbs=v_def_tbs.get().strip() or "USERS",
                                               temp_tbs=v_tmp_tbs.get().strip() or "TEMP",
                                               quota_mb=int(v_quota.get()))
                
                messagebox.showinfo("Success",
                                    f"User '{new_user}' created (Oracle user: {oracle_uname}).\n"
                                    f"Granted SELECT on {len(tables)} tables of schema {v_schema.get().strip().upper()}.")
            except Exception as e:
                messagebox.showerror("Registration failed", f"Could not create user or grant privileges:\n{e}")

        ttk.Button(dlg, text="Create", command=on_create).grid(row=7, column=0, padx=pad, pady=(15, 10), sticky="e")
        ttk.Button(dlg, text="Close", command=dlg.destroy).grid(row=7, column=1, padx=pad, pady=(15, 10), sticky="w")

    def _load_selected_table(self):
        table = self.combo_tables.get()
        if not table:
            messagebox.showwarning("No table selected", "Please choose a table first.")
            return
        try:
            cols, rows = fetch_table_preview(self.conn, table, limit=200)
        except Exception as e:
            messagebox.showerror("Query error", str(e))
            return

        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = cols
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120, stretch=True, anchor="w")

        for r in rows:
            disp = [("" if v is None else str(v)) for v in r]
            self.tree.insert("", "end", values=disp)

    def _show_load_data_form(self):
        """
        Open the current 'load data' view. Rebuilds the main frame so the
        existing load-data controls are shown (table chooser + Load data).
        """
        try:
            self._build_main_frame()
        except Exception as e:
            messagebox.showerror("Error", f"Không thể mở form Load data:\n{e}")

# ------------------------------- MAIN -------------------------------------
if __name__ == "__main__":
    app = OracleApp()
    app.mainloop()
