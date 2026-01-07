"""
Module hiển thị thông tin người dùng và quyền truy cập
Chỉ dành cho admin (LOCB2, SYS, hoặc có quyền DBA)
Bao gồm chức năng kill session
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

from modules.monitor_form import open_monitor_form

try:
    import oracledb
except ImportError:
    oracledb = None


def check_admin_privileges(conn):
    """
    Kiểm tra xem user hiện tại có quyền admin không
    Returns: (is_admin: bool, username: str)
    """
    try:
        cur = conn.cursor()
        
        # Lấy username hiện tại
        cur.execute("SELECT USER FROM DUAL")
        current_user = cur.fetchone()[0].upper()
        
        # Kiểm tra nếu là LOCB2 hoặc SYS
        if current_user in ('LOCB2', 'SYS', 'SYSTEM'):
            return True, current_user
        
        # Kiểm tra có role DBA không
        cur.execute("""
            SELECT COUNT(*) 
            FROM USER_ROLE_PRIVS 
            WHERE GRANTED_ROLE = 'DBA'
        """)
        has_dba = cur.fetchone()[0] > 0
        
        return has_dba, current_user
    except Exception:
        return False, "UNKNOWN"


def get_connected_users(conn):
    """
    Lấy danh sách người dùng đang kết nối
    Returns: List of tuples (username, sid, serial, status, machine, program, logon_time)
    """
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                s.username,
                s.sid,
                s.serial#,
                s.status,
                s.machine,
                s.program,
                TO_CHAR(s.logon_time, 'YYYY-MM-DD HH24:MI:SS') as logon_time,
                s.osuser
            FROM v$session s
            WHERE s.type = 'USER'
              AND s.username IS NOT NULL
            ORDER BY s.logon_time DESC
        """)
        return cur.fetchall()
    except Exception as e:
        print(f"Lỗi khi lấy danh sách user: {e}")
        return []


def get_users_with_access(conn, owner_name='LOCB2'):
    """
    Lấy danh sách user có quyền truy cập vào các bảng của owner
    Returns: List of tuples (username, table_count)
    """
    try:
        cur = conn.cursor()
        
        # Lấy danh sách (grantee, table_name) như trong dtb_manager.py
        sql = """
            SELECT GRANTEE, TABLE_NAME 
            FROM DBA_TAB_PRIVS 
            WHERE OWNER = :owner 
              AND PRIVILEGE = 'SELECT'
              AND GRANTEE NOT IN ('SYS', 'SYSTEM', 'PUBLIC')
        """
        cur.execute(sql, owner=owner_name.upper())
        rows = cur.fetchall()
        
        # Nhóm theo user và đếm số bảng
        user_tables = {}
        for grantee, table_name in rows:
            if grantee not in user_tables:
                user_tables[grantee] = []
            user_tables[grantee].append(table_name)
        
        # Chuyển thành list of tuples (username, table_count)
        result = [(username, len(tables)) for username, tables in user_tables.items()]
        result.sort(key=lambda x: x[0])  # Sort by username
        
        cur.close()
        return result
        
    except Exception as e:
        print(f"Lỗi khi lấy danh sách quyền: {e}")
        return []


def get_user_privileges_on_locb2(conn, username):
    """
    Lấy chi tiết quyền của một user trên các bảng LOCB2
    Returns: List of tuples (table_name, privilege, grantable)
    """
    try:
        cur = conn.cursor()
        
        # Dùng DBA_TAB_PRIVS với OWNER thay vì table_owner
        sql = """
            SELECT 
                TABLE_NAME,
                PRIVILEGE,
                GRANTABLE
            FROM DBA_TAB_PRIVS
            WHERE OWNER = 'LOCB2'
              AND GRANTEE = :username
            ORDER BY TABLE_NAME, PRIVILEGE
        """
        cur.execute(sql, username=username.upper())
        rows = cur.fetchall()
        cur.close()
        return rows
        
    except Exception as e:
        print(f"Lỗi khi lấy chi tiết quyền: {e}")
        return []


def kick_user_by_username(conn, target_username):
    """
    Admin đá user ra khỏi hệ thống (Gửi Alert -> Đợi -> Kill All)
    Hoạt động giống logout_all_other_sessions nhưng dành cho Admin
    
    Args:
        conn: Kết nối Oracle
        target_username: Username cần kick
    
    Returns:
        (session_count: int, message: str)
    """
    cursor = conn.cursor()
    try:
        # 1. Lấy SID của Admin (để không tự sát)
        cursor.execute("SELECT SYS_CONTEXT('USERENV', 'SID') FROM DUAL")
        admin_sid = str(cursor.fetchone()[0])

        # 2. Tìm tất cả session của user mục tiêu
        cursor.execute("""
            SELECT sid, serial#, machine, program
            FROM v$session
            WHERE username = :uname
              AND type = 'USER'
        """, {'uname': target_username.upper()})
        
        sessions = cursor.fetchall()
        if not sessions:
            return 0, "User này không có kết nối nào."

        # 3. Gửi tín hiệu nhẹ nhàng (DBMS_ALERT)
        alert_name = f'LOGOUT_ALERT_{target_username.upper()}'
        try:
            cursor.callproc('DBMS_ALERT.SIGNAL', [alert_name, 'LOGOUT_NOW'])
            conn.commit()
            print(f"🔔 Đã gửi DBMS_ALERT đến {target_username}")
        except Exception as e:
            print(f"⚠️ Không gửi được alert: {e}")
            pass  # Bỏ qua nếu lỗi gửi alert

        # Đợi 1 chút cho client tự thoát
        time.sleep(1.0)

        # 4. Kill tàn dư (Những session chưa chịu thoát)
        kill_count = 0
        for sid, serial, machine, program in sessions:
            # BẢO VỆ: Không bao giờ kill chính Admin đang thao tác
            if str(sid) == admin_sid:
                print(f"⚠️ Bỏ qua session {sid} (chính Admin)")
                continue

            try:
                # Kiểm tra lại xem nó còn sống không
                cursor.execute("SELECT count(*) FROM v$session WHERE sid=:s AND serial#=:r",
                             {'s': sid, 'r': serial})
                if cursor.fetchone()[0] == 0:
                    print(f"✅ Session {sid},{serial} đã tự thoát")
                    continue  # Đã tự thoát rồi

                # Kill dứt khoát
                cursor.execute(f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE")
                kill_count += 1
                print(f"💀 Đã kill session {sid},{serial} ({machine})")
            except oracledb.DatabaseError as e:
                # Bỏ qua lỗi ORA-00031 (đang dọn dẹp) hoặc ORA-00030/00027 (đã chết)
                if e.args[0].code not in (27, 30, 31):
                    print(f"❌ Lỗi kill {sid}: {e}")

        conn.commit()
        return len(sessions), f"Đã gửi lệnh đăng xuất tới user {target_username}.\nĐã kill cưỡng chế {kill_count} session."

    except Exception as e:
        print(f"❌ Lỗi kick_user_by_username: {e}")
        return 0, f"Lỗi: {e}"
    finally:
        cursor.close()


def kill_session(conn, sid, serial):
    """
    Admin kill một session cụ thể (KHÔNG gửi DBMS_ALERT)
    
    Args:
        conn: Kết nối Oracle
        sid: Session ID
        serial: Serial number
    
    Returns:
        (success: bool, message: str)
    """
    cursor = conn.cursor()
    try:
        # 1. BƯỚC BẢO VỆ: Kiểm tra xem có đang định kill chính mình không
        cursor.execute("SELECT SYS_CONTEXT('USERENV', 'SID') FROM DUAL")
        my_sid = str(cursor.fetchone()[0])
        
        if str(sid) == my_sid:
            print(f"🚨 NGUY HIỂM: Admin cố kill chính mình (SID={sid})")
            return False, "⛔ NGUY HIỂM: Không thể kill session của chính Admin!"

        # 2. Lấy thông tin session trước khi kill
        cursor.execute("""
            SELECT username, machine, program
            FROM v$session
            WHERE sid = :sid AND serial# = :serial
        """, {'sid': sid, 'serial': serial})
        
        result = cursor.fetchone()
        if not result:
            print(f"⚠️ Session SID={sid}, Serial={serial} không tồn tại")
            return False, f"Session SID={sid}, Serial={serial} không tồn tại"
        
        username, machine, program = result
        print(f"🎯 Killing session: {username}@{machine} (SID={sid}, Serial={serial})")

        # 3. THỰC HIỆN KILL - Chỉ dùng ALTER SYSTEM, KHÔNG gửi DBMS_ALERT
        sql = f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE"
        cursor.execute(sql)
        conn.commit()
        
        print(f"✅ Successfully killed session {sid},{serial}")
        return True, f"✅ Đã kill session: {username}@{machine}\nSID={sid}, Serial={serial}"

    except oracledb.DatabaseError as e:
        error, = e.args
        
        # 4. XỬ LÝ LỖI ORA-00031 (Session marked for kill)
        # Đây thực chất là thành công nhưng Oracle báo lỗi vì session chưa dọn dẹp xong
        if error.code == 31:
            print(f"⏳ Session {sid},{serial} đang được dọn dẹp ngầm")
            return True, "✅ Đã gửi lệnh Kill (Session đang được dọn dẹp ngầm)."
        
        # Lỗi ORA-00027 hoặc ORA-00030: Session không tồn tại (có thể user đã tự thoát)
        elif error.code in (27, 30):
            print(f"⚠️ Session {sid},{serial} đã kết thúc từ trước")
            return True, "✅ Session này đã kết thúc từ trước."
            
        else:
            print(f"❌ Lỗi Oracle {error.code}: {str(e)}")
            return False, f"❌ Lỗi Oracle: {str(e)}"
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False, f"❌ Lỗi: {e}"
        
    finally:
        cursor.close()


def get_session_statistics(conn):
    """
    Lấy thống kê về các phiên kết nối
    Returns: dict với các key: total, active, inactive
    """
    try:
        cur = conn.cursor()
        
        # Tổng số phiên user
        cur.execute("""
            SELECT COUNT(*) 
            FROM v$session 
            WHERE type = 'USER' AND username IS NOT NULL
        """)
        total = cur.fetchone()[0]
        
        # Phiên đang active
        cur.execute("""
            SELECT COUNT(*) 
            FROM v$session 
            WHERE type = 'USER' 
              AND username IS NOT NULL 
              AND status = 'ACTIVE'
        """)
        active = cur.fetchone()[0]
        
        return {
            'total': total,
            'active': active,
            'inactive': total - active
        }
    except Exception:
        return {'total': 0, 'active': 0, 'inactive': 0}


class UserViewerForm:
    """Form hiển thị thông tin user, quyền và kill session (thread-safe)"""
    
    def __init__(self, parent, conn):
        self.conn = conn
        self.db_lock = threading.Lock()  # Bảo vệ truy cập DB khỏi nhiều thread
        self.window = tk.Toplevel(parent)
        self.window.title("Quản Lý User & Kill Session")
        self.window.geometry("900x600")
        self.window.transient(parent)
        
        # Kiểm tra quyền admin
        is_admin, username = check_admin_privileges(conn)
        if not is_admin:
            messagebox.showerror("Từ Chối Truy Cập",
                f"Chức năng này chỉ dành cho quản trị viên!\n\n"
                f"Người dùng hiện tại: {username}\n"
                f"Cần có quyền DBA hoặc là tài khoản LOCB2/SYS.")
            self.window.destroy()
            return
        
        self._build_ui()
        
    def _build_ui(self):
        """Xây dựng giao diện"""
        # Header với thống kê
        header = ttk.Frame(self.window, padding=10)
        header.pack(fill="x")
        
        ttk.Label(header, text="📊 Quản Lý Người Dùng", 
                 font=("Segoe UI", 14, "bold")).pack(side="left")
        
        # Nút giám sát và refresh
        ttk.Button(header, text="👀 Giám sát hệ thống", 
                  command=lambda: open_monitor_form(self.window, self.conn)).pack(side="right", padx=5)
        ttk.Button(header, text="🔄 Refresh", 
                  command=self._refresh_all).pack(side="right", padx=5)
        
        # Thống kê
        self.stats_label = ttk.Label(header, text="", 
                                     font=("Segoe UI", 9))
        self.stats_label.pack(side="right", padx=10)
        
        # Notebook với 3 tabs
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Tab 1: Người dùng đang kết nối
        self._build_connected_users_tab()
        
        # Tab 2: Quyền truy cập
        self._build_access_rights_tab()
        
        # Tab 3: Chi tiết user
        self._build_user_details_tab()
        
        # Load dữ liệu ban đầu
        self._refresh_all()
    
    def _build_connected_users_tab(self):
        """Tab hiển thị user đang kết nối"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="👤 Đang Kết Nối")
        
        # Toolbar
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(toolbar, text="Danh sách người dùng đang kết nối:",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        
        ttk.Button(toolbar, text="🚫 Kill Session", 
                  command=self._kill_selected_session).pack(side="right", padx=5)
        
        ttk.Button(toolbar, text="Refresh", 
                  command=self.load_connected_users).pack(side="right", padx=5)
        
        # Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        columns = ("Username", "SID", "Serial", "Status", "Machine", "Program", "Logon Time", "OS User")
        self.connected_tree = ttk.Treeview(tree_frame, columns=columns, 
                                          show="headings", height=15,
                                          yscrollcommand=vsb.set,
                                          xscrollcommand=hsb.set)
        
        vsb.config(command=self.connected_tree.yview)
        hsb.config(command=self.connected_tree.xview)
        
        # Cấu hình cột
        self.connected_tree.heading("Username", text="Username")
        self.connected_tree.heading("SID", text="SID")
        self.connected_tree.heading("Serial", text="Serial#")
        self.connected_tree.heading("Status", text="Status")
        self.connected_tree.heading("Machine", text="Machine")
        self.connected_tree.heading("Program", text="Program")
        self.connected_tree.heading("Logon Time", text="Logon Time")
        self.connected_tree.heading("OS User", text="OS User")
        
        self.connected_tree.column("Username", width=100)
        self.connected_tree.column("SID", width=60)
        self.connected_tree.column("Serial", width=60)
        self.connected_tree.column("Status", width=80)
        self.connected_tree.column("Machine", width=120)
        self.connected_tree.column("Program", width=150)
        self.connected_tree.column("Logon Time", width=140)
        self.connected_tree.column("OS User", width=100)
        
        # Pack
        self.connected_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Info label
        info = ttk.Label(tab, text="ℹ️ Chọn session và nhấn 'Kill Session' để ngắt kết nối",
                        foreground="blue")
        info.pack(pady=5)
    
    def _build_access_rights_tab(self):
        """Tab hiển thị quyền truy cập"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔐 Quyền Truy Cập")
        
        # Toolbar
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(toolbar, text="Người dùng có quyền truy cập bảng LOCB2:",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        
        ttk.Button(toolbar, text="Refresh", 
                  command=self.load_users_with_access).pack(side="right", padx=5)
        
        # Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        
        columns = ("Username", "Table Count")
        self.access_tree = ttk.Treeview(tree_frame, columns=columns,
                                       show="headings", height=15,
                                       yscrollcommand=vsb.set)
        
        vsb.config(command=self.access_tree.yview)
        
        self.access_tree.heading("Username", text="Username")
        self.access_tree.heading("Table Count", text="Số Bảng Được Truy Cập")
        
        self.access_tree.column("Username", width=200)
        self.access_tree.column("Table Count", width=150)
        
        self.access_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        
        # Bind double-click để xem chi tiết
        self.access_tree.bind("<Double-1>", self._on_access_double_click)
        
        # Info
        info = ttk.Label(tab, text="💡 Double-click vào user để xem chi tiết quyền",
                        foreground="blue")
        info.pack(pady=5)
    
    def _build_user_details_tab(self):
        """Tab chi tiết quyền của user"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📋 Chi Tiết User")
        
        # Search bar
        search_frame = ttk.Frame(tab)
        search_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(search_frame, text="Username:").pack(side="left", padx=5)
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(search_frame, textvariable=self.username_var, width=20)
        username_entry.pack(side="left", padx=5)
        
        ttk.Button(search_frame, text="🔍 Tìm kiếm", 
                  command=self.load_user_details).pack(side="left", padx=5)
        
        # Treeview
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        
        columns = ("Table", "Privilege", "Grantable")
        self.details_tree = ttk.Treeview(tree_frame, columns=columns,
                                        show="headings", height=15,
                                        yscrollcommand=vsb.set)
        
        vsb.config(command=self.details_tree.yview)
        
        self.details_tree.heading("Table", text="Bảng")
        self.details_tree.heading("Privilege", text="Quyền (Nhiều quyền)")
        self.details_tree.heading("Grantable", text="Có Thể Grant")
        
        self.details_tree.column("Table", width=200)
        self.details_tree.column("Privilege", width=300)  # Tăng độ rộng để hiển thị nhiều quyền
        self.details_tree.column("Grantable", width=120)
        
        self.details_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        
        # Info label
        self.details_info = ttk.Label(tab, text="", foreground="blue")
        self.details_info.pack(pady=5)
    
    def _refresh_all(self):
        """Refresh tất cả dữ liệu"""
        self._update_statistics()
        self.load_connected_users()
        self.load_users_with_access()
    
    def _update_statistics(self):
        """Cập nhật thống kê (thread-safe)"""
        with self.db_lock:
            stats = get_session_statistics(self.conn)
        text = f"📊 Tổng: {stats['total']} | 🟢 Active: {stats['active']} | ⚪ Inactive: {stats['inactive']}"
        self.stats_label.config(text=text)
    
    def load_connected_users(self):
        """Load danh sách user đang kết nối (thread-safe)"""
        # Xóa dữ liệu cũ
        for item in self.connected_tree.get_children():
            self.connected_tree.delete(item)
        
        # Load dữ liệu mới trong thread để không block UI
        def _load():
            with self.db_lock:
                users = get_connected_users(self.conn)
            
            def _update_ui():
                for user in users:
                    # Format: username, sid, serial, status, machine, program, logon_time, osuser
                    self.connected_tree.insert("", "end", values=user)
            
            try:
                self.window.after(0, _update_ui)
            except Exception:
                pass
        
        threading.Thread(target=_load, daemon=True).start()
    
    def load_users_with_access(self):
        """Load danh sách user có quyền truy cập (thread-safe)"""
        for item in self.access_tree.get_children():
            self.access_tree.delete(item)
        
        def _load():
            with self.db_lock:
                users = get_users_with_access(self.conn, 'LOCB2')
            
            def _update_ui():
                for username, table_count in users:
                    self.access_tree.insert("", "end", values=(username, table_count))
            
            try:
                self.window.after(0, _update_ui)
            except Exception:
                pass
        
        threading.Thread(target=_load, daemon=True).start()
    
    def load_user_details(self):
        """Load chi tiết quyền của user (thread-safe)"""
        username = self.username_var.get().strip()
        if not username:
            messagebox.showwarning("Thiếu thông tin", 
                                  "Vui lòng nhập username cần tìm!")
            return
        
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
        
        def _load():
            with self.db_lock:
                privileges = get_user_privileges_on_locb2(self.conn, username)
            
            def _update_ui():
                if not privileges:
                    self.details_info.config(
                        text=f"❌ User '{username}' không có quyền truy cập nào trên schema LOCB2")
                else:
                    # Gộp quyền theo bảng
                    table_privs = {}  # {table_name: [privileges]}
                    table_grantable = {}  # {table_name: has_grantable}
                    
                    for table, privilege, grantable in privileges:
                        if table not in table_privs:
                            table_privs[table] = []
                            table_grantable[table] = False
                        table_privs[table].append(privilege)
                        if grantable == "YES":
                            table_grantable[table] = True
                    
                    # Hiển thị
                    total_privs = len(privileges)
                    self.details_info.config(
                        text=f"✅ Tìm thấy {total_privs} quyền trên {len(table_privs)} bảng cho user '{username}'")
                    
                    # Insert theo bảng (gộp quyền)
                    for table in sorted(table_privs.keys()):
                        privs_str = ", ".join(sorted(table_privs[table]))
                        grantable_text = "YES" if table_grantable[table] else "NO"
                        self.details_tree.insert("", "end", 
                                               values=(table, privs_str, grantable_text))
            
            try:
                self.window.after(0, _update_ui)
            except Exception:
                pass
        
        threading.Thread(target=_load, daemon=True).start()
    
    def _kill_selected_session(self):
        """Kick user (logout all sessions) được chọn trong connected users tree"""
        selection = self.connected_tree.selection()
        if not selection:
            messagebox.showwarning("Chưa chọn",
                                  "Vui lòng chọn user cần ngắt kết nối!")
            return
        
        item = self.connected_tree.item(selection[0])
        values = item['values']
        
        target_username = str(values[0])  # Lấy username
        
        # Cảnh báo rõ ràng cho Admin
        confirm = messagebox.askyesno(
            "Xác nhận Logout",
            f"Bạn có muốn (Logout) user '{target_username}' không?\n\n"
            f" LƯU Ý: Hành động này sẽ ngắt kết nối TẤT CẢ các thiết bị\n"
            f"mà user '{target_username}' đang đăng nhập!"
        )
        
        if not confirm:
            return
        
        # Thực hiện trong thread để không đơ UI
        def _do_kick():
            # QUAN TRỌNG: Vẫn phải dùng Lock để tránh crash app Admin
            with self.db_lock:
                count, msg = kick_user_by_username(self.conn, target_username)
            
            # Cập nhật UI
            def _update_ui():
                messagebox.showinfo("Kết quả", msg)
                self.load_connected_users()  # Refresh danh sách
                self._update_statistics()
            
            try:
                self.window.after(0, _update_ui)
            except Exception:
                pass
        
        threading.Thread(target=_do_kick, daemon=True).start()
    
    def _on_access_double_click(self, event):
        """Xử lý double-click trên access tree"""
        selection = self.access_tree.selection()
        if not selection:
            return
        
        item = self.access_tree.item(selection[0])
        username = item['values'][0]
        
        # Chuyển sang tab chi tiết và tìm kiếm
        self.notebook.select(2)  # Tab index 2 = User Details
        self.username_var.set(username)
        self.load_user_details()


def open_user_viewer_form(parent, conn):
    """
    Hàm tiện ích để mở form quản lý user
    
    Args:
        parent: Cửa sổ cha (tk.Tk hoặc tk.Toplevel)
        conn: Connection đến Oracle Database
    
    Returns:
        UserViewerForm instance hoặc None nếu không có quyền
    """
    if conn is None:
        messagebox.showerror("Lỗi", "Không có kết nối database!")
        return None
    
    try:
        return UserViewerForm(parent, conn)
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể mở form quản lý user:\n{e}")
        return None
