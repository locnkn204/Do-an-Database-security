import tkinter as tk
from tkinter import ttk, messagebox
import oracledb

class MonitorForm:
    def __init__(self, parent, conn):
        self.conn = conn
        self.window = tk.Toplevel(parent)
        self.window.title("Hệ Thống Giám Sát (Monitor Center)")
        self.window.geometry("1100x650")
        
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # TAB 1: Session Manager (Real-time) - Xem ai đang online
        self.tab_sessions = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sessions, text="🔴 Phiên làm việc (Real-time)")
        self._build_session_monitor()

        # TAB 2: Login History (Lịch sử đăng nhập) - Xem ai đăng nhập thất bại/thành công
        self.tab_history = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_history, text="🕒 Lịch sử Đăng nhập")
        self._build_login_history()

        # TAB 3: User Actions (Nhật ký hành động) - Xem ai làm gì (Load data, encrypt...)
        self.tab_actions = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_actions, text="📝 Nhật ký Thao tác")
        self._build_action_logs()

    # ================= TAB 1: SESSIONS =================
    def _build_session_monitor(self):
        frame_top = ttk.Frame(self.tab_sessions)
        frame_top.pack(fill="x", pady=5, padx=5)
        
        ttk.Label(frame_top, text="Danh sách người dùng đang kết nối trực tiếp vào Oracle", 
                 font=("Segoe UI", 9, "italic")).pack(side="left")
        
        ttk.Button(frame_top, text="🔄 Làm mới", command=self._load_sessions).pack(side="right")
        
        cols = ("Username", "SID", "Serial#", "Machine", "Logon Time", "Status")
        self.tree_sessions = ttk.Treeview(self.tab_sessions, columns=cols, show="headings", height=15)
        
        for col in cols:
            self.tree_sessions.heading(col, text=col)
            self.tree_sessions.column(col, width=120)
            
        self.tree_sessions.pack(fill="both", expand=True, padx=5, pady=5)
        self._load_sessions()

    def _load_sessions(self):
        for i in self.tree_sessions.get_children():
            self.tree_sessions.delete(i)
        try:
            cur = self.conn.cursor()
            # Query view hệ thống v$session
            cur.execute("""
                SELECT username, sid, serial#, machine, 
                       TO_CHAR(logon_time, 'YYYY-MM-DD HH24:MI:SS'), status
                FROM v$session 
                WHERE type='USER' AND username IS NOT NULL
                ORDER BY logon_time DESC
            """)
            for row in cur.fetchall():
                self.tree_sessions.insert("", "end", values=row)
        except Exception as e:
            print(f"Lỗi load session: {e}")

    # ================= TAB 2: LOGIN HISTORY =================
    def _build_login_history(self):
        frame_top = ttk.Frame(self.tab_history)
        frame_top.pack(fill="x", pady=5, padx=5)
        
        ttk.Label(frame_top, text="Lịch sử đăng nhập/đăng xuất", font=("Segoe UI", 9)).pack(side="left")
        
        # Radio button chọn nguồn dữ liệu
        source_frame = ttk.Frame(frame_top)
        source_frame.pack(side="left", padx=20)
        
        self.history_source = tk.StringVar(value="app")
        ttk.Radiobutton(source_frame, text="📱 App Logs (LOGIN_ATTEMPTS)", 
                       variable=self.history_source, value="app",
                       command=self._load_history).pack(side="left", padx=5)
        ttk.Radiobutton(source_frame, text="🗄️ Oracle Audit (dba_audit_trail)", 
                       variable=self.history_source, value="oracle",
                       command=self._load_history).pack(side="left", padx=5)
        
        ttk.Button(frame_top, text="🔄 Làm mới", command=self._load_history).pack(side="right")
        
        # Treeview - cột sẽ thay đổi tùy theo source
        self.tree_hist = ttk.Treeview(self.tab_history, show="headings", height=15)
        
        # Tạo tag màu sắc
        self.tree_hist.tag_configure('success', foreground='green')
        self.tree_hist.tag_configure('fail', foreground='red')
        self.tree_hist.tag_configure('logon', foreground='green')
        self.tree_hist.tag_configure('logoff', foreground='orange')

        self.tree_hist.pack(fill="both", expand=True, padx=5, pady=5)
        self._load_history()

    def _load_history(self):
        """Load lịch sử login từ App hoặc Oracle Audit"""
        for i in self.tree_hist.get_children():
            self.tree_hist.delete(i)
        
        # Xóa cột cũ nếu có
        for col in self.tree_hist['columns']:
            self.tree_hist.column(col, width=0)
        
        source = self.history_source.get()
        
        if source == "app":
            self._load_history_app()
        else:
            self._load_history_oracle()
    
    def _load_history_app(self):
        """Lấy dữ liệu từ bảng LOGIN_ATTEMPTS (App Logs)"""
        try:
            cols = ("Username", "Trạng thái", "Thời gian")
            self.tree_hist['columns'] = cols
            self.tree_hist.heading("#0", text="")
            
            for col in cols:
                self.tree_hist.heading(col, text=col)
            
            self.tree_hist.column("Username", width=150)
            self.tree_hist.column("Trạng thái", width=150)
            self.tree_hist.column("Thời gian", width=200)
            
            cur = self.conn.cursor()
            cur.execute("""
                SELECT u.USERNAME, 
                       CASE WHEN l.SUCCESS=1 THEN '✅ Thành công' ELSE '❌ Thất bại' END,
                       TO_CHAR(l.ATTEMPT_TIME, 'YYYY-MM-DD HH24:MI:SS')
                FROM LOCB2.LOGIN_ATTEMPTS l
                JOIN LOCB2.USERS u ON l.USER_ID = u.ID
                ORDER BY l.ATTEMPT_TIME DESC
                FETCH FIRST 50 ROWS ONLY
            """)
            
            for row in cur.fetchall():
                tag = 'success' if '✅' in row[1] else 'fail'
                self.tree_hist.insert("", "end", values=row, tags=(tag,))
                
        except Exception as e:
            print(f"⚠️ Lỗi load app history: {e}")
    
    def _load_history_oracle(self):
        """Lấy dữ liệu từ Oracle Audit Trail (dba_audit_trail) bằng Function"""
        try:
            cols = ("Username", "Máy tính", "Hành động", "Kết quả", "Ghi chú", "Thời gian")
            self.tree_hist['columns'] = cols
            self.tree_hist.heading("#0", text="")
            
            for col in cols:
                self.tree_hist.heading(col, text=col)
            
            self.tree_hist.column("Username", width=100)
            self.tree_hist.column("Máy tính", width=120)
            self.tree_hist.column("Hành động", width=80)
            self.tree_hist.column("Kết quả", width=80)
            self.tree_hist.column("Ghi chú", width=150)
            self.tree_hist.column("Thời gian", width=150)
            
            # Gọi function bằng callfunc() với oracledb.CURSOR
            cursor = self.conn.cursor()
            ref_cursor = cursor.callfunc("FN_GET_SESSION_AUDIT", oracledb.CURSOR)
            
            # Lấy dữ liệu từ cursor
            rows = ref_cursor.fetchall()
            
            for row in rows:
                username, userhost, timestamp, action, returncode, comment, sessionid = row
                
                # Format dữ liệu
                result = '✅ Success' if returncode == 0 else f'❌ Failed ({returncode})'
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else 'N/A'
                userhost_clean = userhost.split(':')[0] if userhost else 'Unknown'
                comment_str = comment if comment else ''
                
                tag = 'logon' if 'LOGON' in action else 'logoff'
                self.tree_hist.insert("", "end", 
                                     values=(username, userhost_clean, action, result, comment_str, timestamp_str),
                                     tags=(tag,))
            
            ref_cursor.close()
                
        except Exception as e:
            print(f"⚠️ Lỗi load oracle audit: {e}")
            # Hiển thị hint
            self.tree_hist['columns'] = ("Message",)
            self.tree_hist.heading("Message", text="Lỗi")
            self.tree_hist.column("Message", width=400)
            self.tree_hist.insert("", "end", values=(f"❌ {str(e)[:100]}...",))

    # ================= TAB 3: ACTION LOGS =================
    def _build_action_logs(self):
        frame_top = ttk.Frame(self.tab_actions)
        frame_top.pack(fill="x", pady=5, padx=5)
        
        ttk.Label(frame_top, text="Nhật ký hành động (bao gồm Profile changes, Encrypt, Export...)",
                 font=("Segoe UI", 9, "italic")).pack(side="left")
        
        # Filter frame
        filter_frame = ttk.Frame(frame_top)
        filter_frame.pack(side="right", padx=5)
        
        ttk.Label(filter_frame, text="Lọc:").pack(side="left", padx=2)
        self.filter_var = tk.StringVar(value="ALL")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, 
                                    values=["ALL", "User", "Profile", "Login", "Encrypt", "Decrypt", "Other"],
                                    state="readonly", width=12)
        filter_combo.pack(side="left", padx=2)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self._load_actions())
        
        ttk.Button(filter_frame, text="🔄 Làm mới", command=self._load_actions).pack(side="left", padx=2)
        
        # Treeview với cột mới
        cols = ("ID", "Username", "Loại", "Hành động", "Thời gian")
        self.tree_logs = ttk.Treeview(self.tab_actions, columns=cols, show="headings")
        
        self.tree_logs.heading("ID", text="Log ID")
        self.tree_logs.heading("Username", text="Người dùng")
        self.tree_logs.heading("Loại", text="Loại")
        self.tree_logs.heading("Hành động", text="Chi tiết")
        self.tree_logs.heading("Thời gian", text="Thời gian")
        
        self.tree_logs.column("ID", width=60)
        self.tree_logs.column("Username", width=130)
        self.tree_logs.column("Loại", width=100)
        self.tree_logs.column("Hành động", width=350)
        self.tree_logs.column("Thời gian", width=160)
        
        # Tag màu sắc cho các loại hành động
        self.tree_logs.tag_configure('profile_insert', background='#e8f5e9')  # Xanh lá nhạt
        self.tree_logs.tag_configure('profile_update', background='#fff3e0')  # Cam nhạt
        self.tree_logs.tag_configure('profile_delete', background='#ffebee')  # Đỏ nhạt
        self.tree_logs.tag_configure('user_action', background='#f3e5f5')     # Tím nhạt (User CREATE/LOCK/UNLOCK)
        self.tree_logs.tag_configure('encrypt', background='#fff9c4')         # Vàng nhạt
        self.tree_logs.tag_configure('decrypt', background='#c8e6c9')         # Xanh nhạt
        self.tree_logs.tag_configure('login', background='#e3f2fd')           # Xanh dương nhạt
        self.tree_logs.tag_configure('other', background='#ffffff')           # Trắng
        
        # Scrollbar
        vsb = ttk.Scrollbar(self.tab_actions, orient="vertical", command=self.tree_logs.yview)
        self.tree_logs.configure(yscrollcommand=vsb.set)
        
        self.tree_logs.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        vsb.pack(side="right", fill="y")
        
        # Info footer
        self.logs_info = ttk.Label(self.tab_actions, text="", foreground="blue")
        self.logs_info.pack(side="bottom", pady=5)
        
        # Bind double-click để xem chi tiết
        self.tree_logs.bind("<Double-1>", self._show_log_detail)
        
        self._load_actions()
    
    def _show_log_detail(self, event):
        """Hiển thị chi tiết log khi double-click"""
        selection = self.tree_logs.selection()
        if not selection:
            return
        
        item = self.tree_logs.item(selection[0])
        values = item['values']
        
        if len(values) >= 5:
            log_id, username, log_type, action, timestamp = values
            
            detail_win = tk.Toplevel(self.window)
            detail_win.title(f"Chi tiết Log #{log_id}")
            detail_win.geometry("600x300")
            detail_win.transient(self.window)
            
            # Header
            ttk.Label(detail_win, text=f"📋 Chi tiết Nhật ký #{log_id}", 
                     font=("Segoe UI", 12, "bold")).pack(pady=10)
            
            # Content frame
            content = ttk.Frame(detail_win, padding=20)
            content.pack(fill="both", expand=True)
            
            info_text = f"""
Người dùng: {username}
Loại hành động: {log_type}
Thời gian: {timestamp}

Chi tiết đầy đủ:
{action}
            """
            
            text_widget = tk.Text(content, wrap="word", height=10, font=("Segoe UI", 10))
            text_widget.insert("1.0", info_text.strip())
            text_widget.config(state="disabled")
            text_widget.pack(fill="both", expand=True)
            
            ttk.Button(detail_win, text="Đóng", command=detail_win.destroy).pack(pady=10)

    def _load_actions(self):
        for i in self.tree_logs.get_children():
            self.tree_logs.delete(i)
        try:
            cur = self.conn.cursor()
            
            # Xây dựng WHERE clause dựa trên filter
            filter_val = self.filter_var.get()
            where_clause = ""
            
            if filter_val == "User":
                where_clause = "AND (l.ACTION LIKE '%User:%' OR l.ACTION LIKE 'User:%')"
            elif filter_val == "Profile":
                where_clause = "AND (l.ACTION LIKE '%Profile%')"
            elif filter_val == "Login":
                where_clause = "AND (l.ACTION LIKE '%Login%' OR l.ACTION LIKE '%Đăng nhập%')"
            elif filter_val == "Encrypt":
                where_clause = "AND l.ACTION LIKE 'Encrypt:%'"
            elif filter_val == "Decrypt":
                where_clause = "AND l.ACTION LIKE 'Decrypt:%'"
            elif filter_val == "Other":
                where_clause = """AND l.ACTION NOT LIKE '%Profile%' 
                                   AND l.ACTION NOT LIKE '%User:%'
                                   AND l.ACTION NOT LIKE '%Login%' 
                                   AND l.ACTION NOT LIKE 'Encrypt:%' 
                                   AND l.ACTION NOT LIKE 'Decrypt:%'"""
            
            # Query logs từ bảng LOGS
            query = f"""
                SELECT l.ID, u.USERNAME, l.ACTION, 
                       TO_CHAR(l.TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS')
                FROM LOGS l
                LEFT JOIN USERS u ON l.USER_ID = u.ID
                WHERE 1=1 {where_clause}
                ORDER BY l.TIMESTAMP DESC
                FETCH FIRST 100 ROWS ONLY
            """
            
            cur.execute(query)
            rows = cur.fetchall()
            
            for row in rows:
                log_id, username, action, timestamp = row
                username = username if username else "SYSTEM"
                
                # Phân loại hành động
                action_upper = action.upper()
                
                # User actions (CREATE/LOCK/UNLOCK)
                if action.startswith("User:") or "USER:" in action_upper:
                    if "CREATE" in action_upper or "TẠO" in action_upper:
                        log_type = "User: CREATE"
                        tag = 'user_action'
                    elif "KHÓA" in action_upper or "LOCK" in action_upper:
                        log_type = "User: LOCK"
                        tag = 'user_action'
                    elif "MỞ KHÓA" in action_upper or "UNLOCK" in action_upper:
                        log_type = "User: UNLOCK"
                        tag = 'user_action'
                    elif "DELETE" in action_upper or "XÓA" in action_upper:
                        log_type = "User: DELETE"
                        tag = 'user_action'
                    else:
                        log_type = "User"
                        tag = 'user_action'
                
                # Profile actions
                elif "PROFILE" in action_upper:
                    if "TẠO" in action_upper or "INSERT" in action_upper or "CREATE" in action_upper:
                        log_type = "Profile: CREATE"
                        tag = 'profile_insert'
                    elif "CẬP NHẬT" in action_upper or "UPDATE" in action_upper:
                        log_type = "Profile: UPDATE"
                        tag = 'profile_update'
                    elif "XÓA" in action_upper or "DELETE" in action_upper:
                        log_type = "Profile: DELETE"
                        tag = 'profile_delete'
                    else:
                        log_type = "Profile"
                        tag = 'other'
                
                # Encrypt/Decrypt actions
                elif action.startswith("Encrypt:"):
                    log_type = "Encrypt"
                    tag = 'encrypt'
                elif action.startswith("Decrypt:"):
                    log_type = "Decrypt"
                    tag = 'decrypt'
                
                # Login actions
                elif "LOGIN" in action_upper or "ĐĂNG NHẬP" in action_upper:
                    log_type = "Login"
                    tag = 'login'
                
                # Other actions
                else:
                    log_type = "Other"
                    tag = 'other'
                
                self.tree_logs.insert("", "end", 
                                     values=(log_id, username, log_type, action, timestamp),
                                     tags=(tag,))
            
            # Cập nhật info
            self.logs_info.config(text=f"✅ Hiển thị {len(rows)} nhật ký (Lọc: {filter_val})")
            
        except Exception as e:
            self.logs_info.config(text=f"❌ Lỗi: {str(e)}")
            print(f"Lỗi load logs: {e}")

# Hàm helper để gọi từ bên ngoài
def open_monitor_form(parent, conn):
    MonitorForm(parent, conn)
