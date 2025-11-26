import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import json
import base64

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phần Mềm Ký Số Chuyên Nghiệp")
        self.root.geometry("1200x700")
        self.root.configure(bg="#f0f0f0")
        
        # Danh sách file đã upload
        self.uploaded_files = []
        self.certificate = None
        self.private_key = None
        
        self.setup_ui()
        self.load_certificate_if_exists()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="📝 PHẦN MỀM KÝ SỐ",
            font=("Arial", 24, "bold"),
            fg="white",
            bg="#2c3e50"
        )
        title_label.pack(pady=20)
        
        # Main container
        main_container = tk.Frame(self.root, bg="#f0f0f0")
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_container, bg="white", relief=tk.RAISED, bd=2)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10), pady=0)
        left_panel.config(width=350)
        
        # Control buttons
        control_frame = tk.LabelFrame(
            left_panel,
            text="Chức Năng",
            font=("Arial", 12, "bold"),
            bg="white",
            fg="#2c3e50",
            padx=15,
            pady=15
        )
        control_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Upload button
        upload_btn = tk.Button(
            control_frame,
            text="📤 Upload File",
            command=self.upload_file,
            bg="#3498db",
            fg="white",
            font=("Arial", 11, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=20,
            pady=10,
            width=25
        )
        upload_btn.pack(pady=5)
        
        # Sign button
        sign_btn = tk.Button(
            control_frame,
            text="✍️ Ký Số File",
            command=self.sign_selected_file,
            bg="#27ae60",
            fg="white",
            font=("Arial", 11, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=20,
            pady=10,
            width=25
        )
        sign_btn.pack(pady=5)
        
        # Verify button
        verify_btn = tk.Button(
            control_frame,
            text="🔍 Kiểm Tra Ký Số",
            command=self.verify_signature,
            bg="#f39c12",
            fg="white",
            font=("Arial", 11, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=20,
            pady=10,
            width=25
        )
        verify_btn.pack(pady=5)
        
        # Help button
        help_btn = tk.Button(
            control_frame,
            text="❓ Hướng Dẫn",
            command=self.show_help,
            bg="#34495e",
            fg="white",
            font=("Arial", 11, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=20,
            pady=10,
            width=25
        )
        help_btn.pack(pady=5)
        
        # Remove button
        remove_btn = tk.Button(
            control_frame,
            text="🗑️ Xóa File",
            command=self.remove_selected_file,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 11, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=20,
            pady=10,
            width=25
        )
        remove_btn.pack(pady=5)
        
        # Certificate management
        cert_frame = tk.LabelFrame(
            left_panel,
            text="Quản Lý Chứng Thư Số",
            font=("Arial", 12, "bold"),
            bg="white",
            fg="#2c3e50",
            padx=15,
            pady=15
        )
        cert_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Generate certificate button
        gen_cert_btn = tk.Button(
            cert_frame,
            text="🔐 Tạo Chứng Thư",
            command=self.generate_certificate,
            bg="#9b59b6",
            fg="white",
            font=("Arial", 10, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=15,
            pady=8,
            width=25
        )
        gen_cert_btn.pack(pady=5)
        
        # Load certificate button
        load_cert_btn = tk.Button(
            cert_frame,
            text="📂 Tải Chứng Thư",
            command=self.load_certificate,
            bg="#16a085",
            fg="white",
            font=("Arial", 10, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=15,
            pady=8,
            width=25
        )
        load_cert_btn.pack(pady=5)
        
        # Certificate info
        self.cert_info = tk.Label(
            cert_frame,
            text="Chưa có chứng thư",
            font=("Arial", 9),
            bg="white",
            fg="#7f8c8d",
            wraplength=280,
            justify=tk.LEFT
        )
        self.cert_info.pack(pady=10)
        
        # File info panel
        info_frame = tk.LabelFrame(
            left_panel,
            text="Thông Tin File",
            font=("Arial", 12, "bold"),
            bg="white",
            fg="#2c3e50",
            padx=15,
            pady=15
        )
        info_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        self.file_info_text = scrolledtext.ScrolledText(
            info_frame,
            height=8,
            font=("Arial", 9),
            bg="#ecf0f1",
            wrap=tk.WORD
        )
        self.file_info_text.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - File list
        right_panel = tk.Frame(main_container, bg="white", relief=tk.RAISED, bd=2)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # File list header
        list_header = tk.Label(
            right_panel,
            text="Danh Sách File Đã Upload",
            font=("Arial", 14, "bold"),
            bg="white",
            fg="#2c3e50",
            pady=15
        )
        list_header.pack()
        
        # Treeview for file list
        tree_frame = tk.Frame(right_panel, bg="white")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        # Treeview
        columns = ("Tên File", "Loại", "Kích Thước", "Trạng Thái", "Ngày Upload")
        self.file_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            height=20
        )
        
        vsb.config(command=self.file_tree.yview)
        hsb.config(command=self.file_tree.xview)
        
        # Configure columns
        self.file_tree.heading("Tên File", text="Tên File")
        self.file_tree.heading("Loại", text="Loại")
        self.file_tree.heading("Kích Thước", text="Kích Thước")
        self.file_tree.heading("Trạng Thái", text="Trạng Thái")
        self.file_tree.heading("Ngày Upload", text="Ngày Upload")
        
        self.file_tree.column("Tên File", width=300)
        self.file_tree.column("Loại", width=100)
        self.file_tree.column("Kích Thước", width=120)
        self.file_tree.column("Trạng Thái", width=150)
        self.file_tree.column("Ngày Upload", width=200)
        
        # Pack scrollbars and treeview
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind selection
        self.file_tree.bind("<<TreeviewSelect>>", self.on_file_select)
        self.file_tree.bind("<Double-1>", self.on_file_double_click)
        
        # Status bar
        self.status_bar = tk.Label(
            self.root,
            text="Sẵn sàng | Tổng số file: 0",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg="#ecf0f1",
            fg="#2c3e50",
            font=("Arial", 9)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def upload_file(self):
        """Upload file vào hệ thống"""
        file_paths = filedialog.askopenfilenames(
            title="Chọn file để upload",
            filetypes=[
                ("Tất cả file", "*.*"),
                ("PDF", "*.pdf"),
                ("Word", "*.doc;*.docx"),
                ("Excel", "*.xls;*.xlsx"),
                ("Images", "*.jpg;*.jpeg;*.png;*.gif"),
                ("Text", "*.txt"),
            ]
        )
        
        for file_path in file_paths:
            if file_path:
                try:
                    file_name = os.path.basename(file_path)
                    file_size = os.path.getsize(file_path)
                    file_ext = os.path.splitext(file_name)[1].upper()
                    
                    # Kiểm tra file đã tồn tại chưa
                    if any(f['path'] == file_path for f in self.uploaded_files):
                        messagebox.showwarning("Cảnh báo", f"File {file_name} đã được upload!")
                        continue
                    
                    file_info = {
                        'path': file_path,
                        'name': file_name,
                        'size': file_size,
                        'extension': file_ext,
                        'status': 'Chưa ký',
                        'upload_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'signed': False,
                        'signature': None
                    }
                    
                    self.uploaded_files.append(file_info)
                    self.update_file_list()
                    
                    self.status_bar.config(text=f"Đã upload: {file_name}")
                    
                except Exception as e:
                    messagebox.showerror("Lỗi", f"Không thể upload file: {str(e)}")
    
    def update_file_list(self):
        """Cập nhật danh sách file"""
        # Xóa tất cả items cũ
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        # Thêm các file mới
        for file_info in self.uploaded_files:
            size_str = self.format_file_size(file_info['size'])
            status = "✅ Đã ký" if file_info['signed'] else "❌ Chưa ký"
            
            self.file_tree.insert(
                "",
                tk.END,
                values=(
                    file_info['name'],
                    file_info['extension'],
                    size_str,
                    status,
                    file_info['upload_date']
                ),
                tags=(file_info['path'],)
            )
        
        # Update status bar
        total = len(self.uploaded_files)
        signed = sum(1 for f in self.uploaded_files if f['signed'])
        self.status_bar.config(text=f"Sẵn sàng | Tổng số file: {total} | Đã ký: {signed}")
    
    def format_file_size(self, size):
        """Format kích thước file"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def on_file_select(self, event):
        """Xử lý khi chọn file"""
        selection = self.file_tree.selection()
        if selection:
            item = self.file_tree.item(selection[0])
            file_path = item['tags'][0] if item['tags'] else None
            
            if file_path:
                file_info = next((f for f in self.uploaded_files if f['path'] == file_path), None)
                if file_info:
                    self.display_file_info(file_info)
    
    def on_file_double_click(self, event):
        """Xử lý khi double-click file"""
        selection = self.file_tree.selection()
        if selection:
            item = self.file_tree.item(selection[0])
            file_path = item['tags'][0] if item['tags'] else None
            
            if file_path:
                try:
                    os.startfile(file_path)
                except Exception:
                    messagebox.showinfo("Thông tin", "Không thể mở file này")
    
    def display_file_info(self, file_info):
        """Hiển thị thông tin file"""
        info = f"""TÊN FILE: {file_info['name']}
ĐƯỜNG DẪN: {file_info['path']}
LOẠI FILE: {file_info['extension']}
KÍCH THƯỚC: {self.format_file_size(file_info['size'])}
TRẠNG THÁI: {'✅ Đã ký số' if file_info['signed'] else '❌ Chưa ký số'}
NGÀY UPLOAD: {file_info['upload_date']}
"""
        
        if file_info['signed'] and file_info.get('signature_info'):
            info += f"\nTHÔNG TIN CHỮ KÝ:\n{file_info['signature_info']}"
        
        self.file_info_text.delete(1.0, tk.END)
        self.file_info_text.insert(1.0, info)
    
    def remove_selected_file(self):
        """Xóa file đã chọn"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file cần xóa!")
            return
        
        item = self.file_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if file_path:
            file_info = next((f for f in self.uploaded_files if f['path'] == file_path), None)
            if file_info:
                if messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn xóa file '{file_info['name']}'?"):
                    self.uploaded_files.remove(file_info)
                    self.update_file_list()
                    self.file_info_text.delete(1.0, tk.END)
                    self.status_bar.config(text=f"Đã xóa: {file_info['name']}")
    
    def generate_certificate(self):
        """Tạo chứng thư số mới"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Tạo Chứng Thư Số")
        dialog.geometry("500x400")
        dialog.configure(bg="white")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        tk.Label(dialog, text="Tên người dùng:", bg="white", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, padx=20, pady=10)
        name_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        name_entry.grid(row=0, column=1, padx=20, pady=10)
        
        tk.Label(dialog, text="Email:", bg="white", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, padx=20, pady=10)
        email_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        email_entry.grid(row=1, column=1, padx=20, pady=10)
        
        tk.Label(dialog, text="Tổ chức:", bg="white", font=("Arial", 10)).grid(row=2, column=0, sticky=tk.W, padx=20, pady=10)
        org_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        org_entry.grid(row=2, column=1, padx=20, pady=10)
        
        tk.Label(dialog, text="Quốc gia (VN):", bg="white", font=("Arial", 10)).grid(row=3, column=0, sticky=tk.W, padx=20, pady=10)
        country_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        country_entry.insert(0, "VN")
        country_entry.grid(row=3, column=1, padx=20, pady=10)
        
        def create_cert():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            org = org_entry.get().strip()
            country = country_entry.get().strip() or "VN"
            
            if not name:
                messagebox.showerror("Lỗi", "Vui lòng nhập tên!")
                return
            
            try:
                # Generate private key
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Create certificate
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, org or "Unknown"),
                    x509.NameAttribute(NameOID.COMMON_NAME, name),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email or "unknown@example.com"),
                ])
                
                cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    self.private_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.now()
                ).not_valid_after(
                    datetime.now().replace(year=datetime.now().year + 1)
                ).sign(self.private_key, hashes.SHA256())
                
                self.certificate = cert
                
                # Save certificate
                self.save_certificate()
                
                cert_info = f"Tên: {name}\nEmail: {email}\nTổ chức: {org}\nQuốc gia: {country}\nHết hạn: {cert.not_valid_after.strftime('%Y-%m-%d')}"
                self.cert_info.config(text=cert_info, fg="#27ae60")
                
                messagebox.showinfo("Thành công", "Đã tạo chứng thư số thành công!")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể tạo chứng thư: {str(e)}")
        
        tk.Button(
            dialog,
            text="Tạo Chứng Thư",
            command=create_cert,
            bg="#27ae60",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=20,
            pady=5
        ).grid(row=4, column=0, columnspan=2, pady=20)
    
    def load_certificate(self):
        """Tải chứng thư số từ file"""
        cert_path = filedialog.askopenfilename(
            title="Chọn file chứng thư",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if cert_path:
            try:
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                
                # Try to load as certificate
                try:
                    self.certificate = x509.load_pem_x509_certificate(cert_data)
                except Exception:
                    # Try to load as certificate request
                    messagebox.showerror("Lỗi", "Định dạng file không đúng!")
                    return
                
                # Load private key if exists
                key_path = cert_path.replace('.pem', '_key.pem')
                if os.path.exists(key_path):
                    with open(key_path, 'rb') as f:
                        key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(key_data, password=None)
                
                self.save_certificate()
                self.update_cert_info()
                messagebox.showinfo("Thành công", "Đã tải chứng thư thành công!")
                
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể tải chứng thư: {str(e)}")
    
    def load_certificate_if_exists(self):
        """Tự động tải chứng thư nếu có"""
        cert_file = "certificate.pem"
        key_file = "private_key.pem"
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                self.certificate = x509.load_pem_x509_certificate(cert_data)
                
                with open(key_file, 'rb') as f:
                    key_data = f.read()
                self.private_key = serialization.load_pem_private_key(key_data, password=None)
                
                self.update_cert_info()
            except Exception:
                pass
    
    def save_certificate(self):
        """Lưu chứng thư ra file"""
        if self.certificate and self.private_key:
            try:
                # Save certificate
                with open("certificate.pem", "wb") as f:
                    f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
                
                # Save private key
                with open("private_key.pem", "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
            except Exception:
                pass
    
    def update_cert_info(self):
        """Cập nhật thông tin chứng thư trên UI"""
        if self.certificate:
            subject = self.certificate.subject
            name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            email = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value if subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS) else "N/A"
            org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else "N/A"
            expiry = self.certificate.not_valid_after.strftime('%Y-%m-%d')
            
            info = f"Tên: {name}\nEmail: {email}\nTổ chức: {org}\nHết hạn: {expiry}"
            self.cert_info.config(text=info, fg="#27ae60")
        else:
            self.cert_info.config(text="Chưa có chứng thư", fg="#7f8c8d")
    
    def sign_selected_file(self):
        """Ký số file đã chọn"""
        if not self.certificate or not self.private_key:
            messagebox.showerror("Lỗi", "Vui lòng tạo hoặc tải chứng thư số trước!")
            return
        
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file cần ký số!")
            return
        
        item = self.file_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if file_path:
            file_info = next((f for f in self.uploaded_files if f['path'] == file_path), None)
            if file_info:
                if file_info['signed']:
                    if not messagebox.askyesno("Xác nhận", "File này đã được ký. Bạn có muốn ký lại không?"):
                        return
                
                try:
                    # Read file content
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                    
                    # Calculate hash
                    file_hash = hashlib.sha256(file_content).digest()
                    
                    # Sign hash
                    signature = self.private_key.sign(
                        file_hash,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    
                    # Encode signature to base64
                    signature_b64 = base64.b64encode(signature).decode('utf-8')
                    
                    # Save signature info
                    file_info['signature'] = signature_b64
                    file_info['signed'] = True
                    file_info['status'] = 'Đã ký'
                    
                    subject = self.certificate.subject
                    name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    sign_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    file_info['signature_info'] = f"Người ký: {name}\nNgày ký: {sign_date}\nThuật toán: SHA256 với RSA-PSS"
                    
                    # Save signed file
                    self.save_signed_file(file_info)
                    
                    self.update_file_list()
                    self.display_file_info(file_info)
                    self.status_bar.config(text=f"Đã ký số file: {file_info['name']}")
                    
                    messagebox.showinfo("Thành công", f"Đã ký số file '{file_info['name']}' thành công!")
                    
                except Exception as e:
                    messagebox.showerror("Lỗi", f"Không thể ký số file: {str(e)}")
    
    def save_signed_file(self, file_info):
        """Lưu file đã ký số"""
        try:
            # Tạo thư mục signed_files nếu chưa có
            signed_dir = "signed_files"
            if not os.path.exists(signed_dir):
                os.makedirs(signed_dir)
            
            # Tạo tên file mới
            base_name = os.path.splitext(file_info['name'])[0]
            ext = os.path.splitext(file_info['name'])[1]
            signed_name = f"{base_name}_signed{ext}"
            signed_path = os.path.join(signed_dir, signed_name)
            
            # Copy file gốc
            import shutil
            shutil.copy2(file_info['path'], signed_path)
            
            # Lưu thông tin chữ ký vào file metadata
            metadata = {
                'original_file': file_info['name'],
                'signed_file': signed_name,
                'signature': file_info['signature'],
                'signature_info': file_info.get('signature_info', ''),
                'sign_date': datetime.now().isoformat()
            }
            
            metadata_file = os.path.join(signed_dir, f"{base_name}_metadata.json")
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
            
            file_info['signed_path'] = signed_path
            
        except Exception as e:
            print(f"Lỗi khi lưu file đã ký: {str(e)}")
    
    def verify_signature(self):
        """Kiểm tra chữ ký số của file đã chọn"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file cần kiểm tra!")
            return
        
        item = self.file_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if not file_path:
            messagebox.showerror("Lỗi", "Không tìm thấy file!")
            return
        
        file_info = next((f for f in self.uploaded_files if f['path'] == file_path), None)
        if not file_info:
            messagebox.showerror("Lỗi", "Không tìm thấy thông tin file!")
            return
        
        # Kiểm tra file đã được ký chưa
        if not file_info.get('signed') or not file_info.get('signature'):
            messagebox.showwarning("Cảnh báo", "File này chưa được ký số!")
            return
        
        try:
            # Đọc file gốc
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Tính hash của file
            file_hash = hashlib.sha256(file_content).digest()
            
            # Decode signature
            signature_b64 = file_info['signature']
            signature = base64.b64decode(signature_b64)
            
            # Kiểm tra chứng thư
            if not self.certificate:
                # Thử tải chứng thư từ file đã ký
                signed_path = file_info.get('signed_path')
                if signed_path:
                    metadata_file = signed_path.replace('_signed', '_metadata').replace(os.path.splitext(signed_path)[1], '.json')
                    if os.path.exists(metadata_file):
                        # File đã ký có metadata, nhưng cần chứng thư để verify
                        messagebox.showwarning("Cảnh báo", "Cần chứng thư số để kiểm tra chữ ký!")
                        return
                
                messagebox.showerror("Lỗi", "Không có chứng thư số để kiểm tra!")
                return
            
            # Lấy public key từ certificate
            public_key = self.certificate.public_key()
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    file_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Kiểm tra thêm tính toàn vẹn của file
                signed_path = file_info.get('signed_path')
                if signed_path and os.path.exists(signed_path):
                    with open(signed_path, 'rb') as f:
                        signed_content = f.read()
                    signed_hash = hashlib.sha256(signed_content).digest()
                    
                    if signed_hash == file_hash:
                        integrity_check = "✅ File không bị thay đổi"
                    else:
                        integrity_check = "⚠️ File đã bị thay đổi sau khi ký!"
                else:
                    integrity_check = "ℹ️ Không thể kiểm tra tính toàn vẹn"
                
                # Kiểm tra thời hạn chứng thư
                now = datetime.now()
                cert_valid = "✅ Chứng thư còn hiệu lực" if now < self.certificate.not_valid_after else "⚠️ Chứng thư đã hết hạn"
                
                # Hiển thị kết quả
                result_window = tk.Toplevel(self.root)
                result_window.title("Kết Quả Kiểm Tra Chữ Ký")
                result_window.geometry("600x500")
                result_window.configure(bg="white")
                result_window.transient(self.root)
                
                # Header
                header = tk.Label(
                    result_window,
                    text="🔍 KẾT QUẢ KIỂM TRA CHỮ KÝ SỐ",
                    font=("Arial", 16, "bold"),
                    bg="white",
                    fg="#27ae60",
                    pady=20
                )
                header.pack()
                
                # Result text
                result_text = scrolledtext.ScrolledText(
                    result_window,
                    height=20,
                    font=("Arial", 11),
                    bg="#ecf0f1",
                    wrap=tk.WORD,
                    padx=20,
                    pady=20
                )
                result_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
                
                # Build result message
                subject = self.certificate.subject
                name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "N/A"
                email = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value if subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS) else "N/A"
                org = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else "N/A"
                
                result_msg = f"""
═══════════════════════════════════════════════════════
                    KẾT QUẢ KIỂM TRA
═══════════════════════════════════════════════════════

📄 TÊN FILE: {file_info['name']}

✅ TRẠNG THÁI CHỮ KÝ: HỢP LỆ
   Chữ ký số đã được xác thực thành công!

👤 THÔNG TIN NGƯỜI KÝ:
   • Tên: {name}
   • Email: {email}
   • Tổ chức: {org}
   • Ngày ký: {file_info.get('signature_info', 'N/A')}

🔐 THÔNG TIN CHỨNG THƯ:
   • Số seri: {self.certificate.serial_number}
   • Có hiệu lực từ: {self.certificate.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')}
   • Hết hạn: {self.certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}
   • Trạng thái: {cert_valid}

🔒 TÍNH TOÀN VẸN FILE:
   {integrity_check}

📊 THUẬT TOÁN:
   • Hash: SHA-256
   • Ký số: RSA-PSS với SHA-256
   • Độ dài khóa: 2048 bits

═══════════════════════════════════════════════════════
                CHỮ KÝ ĐƯỢC XÁC THỰC THÀNH CÔNG
═══════════════════════════════════════════════════════
"""
                
                result_text.insert(1.0, result_msg)
                result_text.config(state=tk.DISABLED)
                
                # Close button
                tk.Button(
                    result_window,
                    text="Đóng",
                    command=result_window.destroy,
                    bg="#27ae60",
                    fg="white",
                    font=("Arial", 11, "bold"),
                    padx=30,
                    pady=10
                ).pack(pady=10)
                
                self.status_bar.config(text=f"Đã kiểm tra chữ ký: {file_info['name']} - HỢP LỆ")
                
            except Exception:
                # Signature verification failed
                result_window = tk.Toplevel(self.root)
                result_window.title("Kết Quả Kiểm Tra Chữ Ký")
                result_window.geometry("500x300")
                result_window.configure(bg="white")
                result_window.transient(self.root)
                
                tk.Label(
                    result_window,
                    text="❌ CHỮ KÝ KHÔNG HỢP LỆ",
                    font=("Arial", 16, "bold"),
                    bg="white",
                    fg="#e74c3c",
                    pady=20
                ).pack()
                
                error_text = scrolledtext.ScrolledText(
                    result_window,
                    height=10,
                    font=("Arial", 10),
                    bg="#ecf0f1",
                    wrap=tk.WORD,
                    padx=20,
                    pady=20
                )
                error_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
                
                error_msg = f"""
═══════════════════════════════════════════════════════
                    KẾT QUẢ KIỂM TRA
═══════════════════════════════════════════════════════

📄 TÊN FILE: {file_info['name']}

❌ TRẠNG THÁI CHỮ KÝ: KHÔNG HỢP LỆ

⚠️ CẢNH BÁO:
   Chữ ký số không thể được xác thực!
   
   Có thể do:
   • File đã bị thay đổi sau khi ký
   • Chứng thư số không khớp
   • Chữ ký bị hỏng hoặc không đúng
   • File không được ký bằng chứng thư này

═══════════════════════════════════════════════════════
"""
                
                error_text.insert(1.0, error_msg)
                error_text.config(state=tk.DISABLED)
                
                tk.Button(
                    result_window,
                    text="Đóng",
                    command=result_window.destroy,
                    bg="#e74c3c",
                    fg="white",
                    font=("Arial", 11, "bold"),
                    padx=30,
                    pady=10
                ).pack(pady=10)
                
                self.status_bar.config(text=f"Đã kiểm tra chữ ký: {file_info['name']} - KHÔNG HỢP LỆ")
        
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể kiểm tra chữ ký: {str(e)}")
    
    def show_help(self):
        """Hiển thị hướng dẫn sử dụng"""
        help_window = tk.Toplevel(self.root)
        help_window.title("Hướng Dẫn Sử Dụng")
        help_window.geometry("800x700")
        help_window.configure(bg="white")
        help_window.transient(self.root)
        
        # Header
        header = tk.Label(
            help_window,
            text="📚 HƯỚNG DẪN SỬ DỤNG PHẦN MỀM KÝ SỐ",
            font=("Arial", 18, "bold"),
            bg="white",
            fg="#2c3e50",
            pady=20
        )
        header.pack()
        
        # Help content
        help_text = scrolledtext.ScrolledText(
            help_window,
            height=30,
            font=("Arial", 10),
            bg="#ecf0f1",
            wrap=tk.WORD,
            padx=20,
            pady=20
        )
        help_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        help_content = """
═══════════════════════════════════════════════════════════════════════════════
                    HƯỚNG DẪN SỬ DỤNG PHẦN MỀM KÝ SỐ
═══════════════════════════════════════════════════════════════════════════════

📋 MỤC LỤC:
   1. Giới thiệu
   2. Cài đặt và yêu cầu hệ thống
   3. Tạo chứng thư số
   4. Upload file
   5. Ký số file
   6. Kiểm tra chữ ký
   7. Quản lý file
   8. Câu hỏi thường gặp

═══════════════════════════════════════════════════════════════════════════════

1. GIỚI THIỆU
═══════════════════════════════════════════════════════════════════════════════

   Phần mềm Ký Số là công cụ chuyên nghiệp để ký số các tài liệu điện tử,
   đảm bảo tính xác thực và toàn vẹn của tài liệu. Phần mềm hỗ trợ:
   
   • Ký số nhiều loại file (PDF, Word, Excel, Images, Text, v.v.)
   • Kiểm tra tính hợp lệ của chữ ký
   • Quản lý chứng thư số
   • Xác thực tính toàn vẹn của tài liệu

═══════════════════════════════════════════════════════════════════════════════

2. CÀI ĐẶT VÀ YÊU CẦU HỆ THỐNG
═══════════════════════════════════════════════════════════════════════════════

   YÊU CẦU:
   • Python 3.7 trở lên
   • Các thư viện: tkinter, cryptography, Pillow
   
   CÀI ĐẶT:
   1. Cài đặt Python từ python.org
   2. Cài đặt các thư viện cần thiết:
      pip install cryptography pillow
   3. Chạy chương trình: python appkyso.py

═══════════════════════════════════════════════════════════════════════════════

3. TẠO CHỨNG THƯ SỐ
═══════════════════════════════════════════════════════════════════════════════

   BƯỚC 1: Tạo chứng thư số mới
   • Nhấn nút "🔐 Tạo Chứng Thư"
   • Điền thông tin:
     - Tên người dùng (bắt buộc)
     - Email
     - Tổ chức
     - Quốc gia (mặc định: VN)
   • Nhấn "Tạo Chứng Thư"
   • Chứng thư sẽ được lưu tự động

   BƯỚC 2: Tải chứng thư từ file
   • Nhấn nút "📂 Tải Chứng Thư"
   • Chọn file chứng thư (.pem)
   • Nếu có file private key, đặt cùng tên với _key.pem
   • Chứng thư sẽ được tải và hiển thị thông tin

   LƯU Ý:
   • Chứng thư tự tạo có thời hạn 1 năm
   • Chứng thư sẽ được lưu tự động trong thư mục hiện tại
   • Giữ an toàn file private_key.pem (không chia sẻ!)

═══════════════════════════════════════════════════════════════════════════════

4. UPLOAD FILE
═══════════════════════════════════════════════════════════════════════════════

   CÁCH UPLOAD:
   1. Nhấn nút "📤 Upload File"
   2. Chọn một hoặc nhiều file từ hộp thoại
   3. File sẽ xuất hiện trong danh sách bên phải
   
   HỖ TRỢ CÁC ĐỊNH DẠNG:
   • PDF (.pdf)
   • Word (.doc, .docx)
   • Excel (.xls, .xlsx)
   • Hình ảnh (.jpg, .jpeg, .png, .gif)
   • Text (.txt)
   • Tất cả các file khác
   
   THÔNG TIN HIỂN THỊ:
   • Tên file
   • Loại file
   • Kích thước
   • Trạng thái (Đã ký / Chưa ký)
   • Ngày upload

═══════════════════════════════════════════════════════════════════════════════

5. KÝ SỐ FILE
═══════════════════════════════════════════════════════════════════════════════

   QUY TRÌNH KÝ SỐ:
   1. Đảm bảo đã có chứng thư số (tạo hoặc tải)
   2. Chọn file cần ký từ danh sách
   3. Nhấn nút "✍️ Ký Số File"
   4. Chờ quá trình ký số hoàn tất
   5. File đã ký sẽ được lưu trong thư mục "signed_files"
   
   THÔNG TIN CHỮ KÝ:
   • Người ký: Tên từ chứng thư số
   • Ngày ký: Thời gian ký số
   • Thuật toán: SHA256 với RSA-PSS
   • Hash: SHA-256 của nội dung file
   
   FILE ĐÃ KÝ:
   • File gốc được sao chép với tên: [tên]_signed.[đuôi]
   • Thông tin chữ ký lưu trong: [tên]_metadata.json
   • File gốc vẫn giữ nguyên

   LƯU Ý:
   • File đã ký có thể ký lại (ghi đè chữ ký cũ)
   • Mỗi lần ký tạo chữ ký mới với thời gian hiện tại
   • Chữ ký được mã hóa Base64 và lưu kèm file

═══════════════════════════════════════════════════════════════════════════════

6. KIỂM TRA CHỮ KÝ
═══════════════════════════════════════════════════════════════════════════════

   CÁCH KIỂM TRA:
   1. Chọn file đã ký từ danh sách
   2. Nhấn nút "🔍 Kiểm Tra Ký Số"
   3. Xem kết quả trong cửa sổ mới
   
   THÔNG TIN KIỂM TRA:
   • Trạng thái chữ ký: Hợp lệ / Không hợp lệ
   • Thông tin người ký
   • Thông tin chứng thư (số seri, thời hạn)
   • Tính toàn vẹn file (file có bị thay đổi không)
   • Thuật toán sử dụng
   
   KẾT QUẢ:
   ✅ HỢP LỆ: Chữ ký đúng, file không bị thay đổi
   ❌ KHÔNG HỢP LỆ: Chữ ký sai hoặc file đã bị thay đổi
   
   LƯU Ý:
   • Cần có chứng thư số để kiểm tra
   • File phải đã được ký số trước đó
   • Kiểm tra cả tính toàn vẹn của file

═══════════════════════════════════════════════════════════════════════════════

7. QUẢN LÝ FILE
═══════════════════════════════════════════════════════════════════════════════

   XEM THÔNG TIN FILE:
   • Click vào file trong danh sách để xem chi tiết
   • Thông tin hiển thị ở panel bên trái
   
   MỞ FILE:
   • Double-click vào file để mở bằng ứng dụng mặc định
   
   XÓA FILE:
   1. Chọn file cần xóa
   2. Nhấn nút "🗑️ Xóa File"
   3. Xác nhận xóa
   • Lưu ý: Chỉ xóa khỏi danh sách, không xóa file gốc
   
   FILE ĐÃ KÝ:
   • Được lưu trong thư mục "signed_files"
   • Giữ nguyên file gốc
   • Có thể mở và kiểm tra bất cứ lúc nào

═══════════════════════════════════════════════════════════════════════════════

8. CÂU HỎI THƯỜNG GẶP (FAQ)
═══════════════════════════════════════════════════════════════════════════════

   Q: Chứng thư tự tạo có hợp lệ không?
   A: Chứng thư tự tạo chỉ dùng cho mục đích thử nghiệm. 
      Để ký số chính thức, cần chứng thư từ CA (Certificate Authority) 
      được công nhận.

   Q: File đã ký có thể chỉnh sửa không?
   A: Có thể chỉnh sửa, nhưng khi kiểm tra sẽ báo "không hợp lệ" 
      vì file đã bị thay đổi sau khi ký.

   Q: Có thể ký nhiều file cùng lúc không?
   A: Hiện tại cần ký từng file một. Upload nhiều file, sau đó 
      chọn và ký từng file.

   Q: File đã ký lưu ở đâu?
   A: Trong thư mục "signed_files" cùng thư mục với chương trình.

   Q: Mất chứng thư số thì sao?
   A: Nếu mất chứng thư hoặc private key, không thể ký số mới 
      hoặc kiểm tra chữ ký cũ. Hãy backup các file certificate.pem 
      và private_key.pem.

   Q: Có thể dùng chứng thư từ USB Token không?
   A: Hiện tại phần mềm hỗ trợ file .pem. Để dùng USB Token, 
      cần xuất chứng thư ra file .pem trước.

═══════════════════════════════════════════════════════════════════════════════

📞 HỖ TRỢ:
   Nếu gặp vấn đề, vui lòng kiểm tra:
   • Đã cài đặt đầy đủ thư viện chưa
   • Chứng thư số còn hiệu lực không
   • File có bị hỏng không
   • Quyền truy cập file và thư mục

═══════════════════════════════════════════════════════════════════════════════
"""
        
        help_text.insert(1.0, help_content)
        help_text.config(state=tk.DISABLED)
        
        # Close button
        tk.Button(
            help_window,
            text="Đóng",
            command=help_window.destroy,
            bg="#2c3e50",
            fg="white",
            font=("Arial", 11, "bold"),
            padx=30,
            pady=10
        ).pack(pady=10)


def main():
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
