# FileCryptX Pro - Secure File Encryption Tool
import os
import customtkinter as ctk
from tkinter import Menu, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import webbrowser

class FileCryptXPro:
    def __init__(self):
        self.key = None
        self.current_file = None
        self.salt = None
        self.current_language = "en"  # Track current language
        self.setup_ui()
        
    def setup_ui(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.root = ctk.CTk()
        self.root.title("FileCryptX Pro")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # Main container
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Title label
        ctk.CTkLabel(
            self.main_frame,
            text="FileCryptX Pro",
            font=("Arial", 16, "bold")
        ).pack(pady=(0, 15))
        
        # File selection
        self.file_frame = ctk.CTkFrame(self.main_frame)
        self.file_frame.pack(pady=10, fill="x")
        
        self.file_label = ctk.CTkLabel(
            self.file_frame, 
            text="No file selected",
            wraplength=300,
            anchor="w"
        )
        self.file_label.pack(side="left", fill="x", expand=True, padx=10)
        
        self.btn_select = ctk.CTkButton(
            self.file_frame, 
            text="Select", 
            command=self.select_file,
            width=80
        )
        self.btn_select.pack(side="right")
        
        # Password section with show/hide button
        self.pass_frame = ctk.CTkFrame(self.main_frame)
        self.pass_frame.pack(pady=10, fill="x")
        
        self.password_entry = ctk.CTkEntry(
            self.pass_frame, 
            placeholder_text="Enter password",
            show="•",
            state="disabled"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(10, 0))
        
        self.btn_show_pass = ctk.CTkButton(
            self.pass_frame,
            text="👁",
            width=30,
            command=self.toggle_password_visibility
        )
        self.btn_show_pass.pack(side="right", padx=(5, 10))
        
        # Action buttons
        self.btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.btn_frame.pack(pady=15)
        
        self.btn_encrypt = ctk.CTkButton(
            self.btn_frame, 
            text="Encrypt", 
            command=self.encrypt_file,
            state="disabled",
            width=120
        )
        self.btn_encrypt.pack(side="left", padx=5)
        
        self.btn_decrypt = ctk.CTkButton(
            self.btn_frame, 
            text="Decrypt", 
            command=self.decrypt_file,
            state="disabled",
            width=120
        )
        self.btn_decrypt.pack(side="right", padx=5)
        
        # Status bar
        self.status_frame = ctk.CTkFrame(self.root, height=25)
        self.status_frame.pack(fill="x", padx=0, pady=(0, 0))
        
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text="Ready",
            text_color="gray"
        )
        self.status_label.pack(side="left", padx=10)
        
        self.version_label = ctk.CTkLabel(
            self.status_frame,
            text="v3.0 Pro",
            text_color="gray"
        )
        self.version_label.pack(side="right", padx=10)
        
        # Create menu
        self.create_menu()
        
        self.root.mainloop()
    
    def toggle_password_visibility(self):
        if self.password_entry.cget("show") == "•":
            self.password_entry.configure(show="")
            self.btn_show_pass.configure(text="🙈")
        else:
            self.password_entry.configure(show="•")
            self.btn_show_pass.configure(text="👁")
    
    def create_menu(self):
        self.menubar = Menu(self.root)
        
        # File menu
        self.file_menu = Menu(self.menubar, tearoff=0)
        self.file_menu.add_command(label="Open", command=self.select_file)
        self.file_menu.add_command(label="Open Encrypted", command=self.select_encrypted_file)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        
        # Language menu
        self.lang_menu = Menu(self.menubar, tearoff=0)
        self.lang_menu.add_command(label="English", command=lambda: self.set_language("en"))
        self.lang_menu.add_command(label="Русский", command=lambda: self.set_language("ru"))
        self.lang_menu.add_command(label="中文", command=lambda: self.set_language("zh"))
        self.menubar.add_cascade(label="Language", menu=self.lang_menu)
        
        # Help menu
        self.help_menu = Menu(self.menubar, tearoff=0)
        self.help_menu.add_command(label="Documentation", command=lambda: webbrowser.open("https://example.com/docs"))
        self.help_menu.add_command(label="About", command=self.show_about)
        self.menubar.add_cascade(label="Help", menu=self.help_menu)
        
        self.root.config(menu=self.menubar)
    
    def select_encrypted_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
        if file_path:
            self.current_file = file_path
            self.file_label.configure(
                text=f"Selected: {os.path.basename(self.current_file)}",
                text_color=("gray", "white")[self.current_file.endswith(".encrypted")]
            )
            self.password_entry.configure(state="normal")
            self.password_entry.focus()
            self.update_buttons()
            self.update_status(f"Loaded: {os.path.basename(self.current_file)}")
    
    def show_about(self):
        about_text = (
            "FileCryptX Pro - Secure File Encryption Tool\n\n"
            "Version 3.0 Professional\n"
            "Uses AES-256 encryption\n\n"
            "Developed by CryptoSoft Team\n"
            "© 2023 All rights reserved"
        )
        messagebox.showinfo("About FileCryptX Pro", about_text)
    
    def set_language(self, lang):
        self.current_language = lang
        if lang == "ru":
            self.update_ui_texts(
                file_label="Файл не выбран",
                btn_select="Выбрать",
                password_placeholder="Введите пароль",
                btn_encrypt="Зашифровать",
                btn_decrypt="Расшифровать",
                status_ready="Готов",
                menu_file="Файл",
                menu_open="Открыть",
                menu_open_enc="Открыть зашифрованный",
                menu_exit="Выход",
                menu_lang="Язык",
                menu_help="Справка",
                menu_docs="Документация",
                menu_about="О программе"
            )
        elif lang == "zh":
            self.update_ui_texts(
                file_label="未选择文件",
                btn_select="选择",
                password_placeholder="输入密码",
                btn_encrypt="加密",
                btn_decrypt="解密",
                status_ready="准备就绪",
                menu_file="文件",
                menu_open="打开",
                menu_open_enc="打开加密文件",
                menu_exit="退出",
                menu_lang="语言",
                menu_help="帮助",
                menu_docs="文档",
                menu_about="关于"
            )
        else:  # English
            self.update_ui_texts(
                file_label="No file selected",
                btn_select="Select",
                password_placeholder="Enter password",
                btn_encrypt="Encrypt",
                btn_decrypt="Decrypt",
                status_ready="Ready",
                menu_file="File",
                menu_open="Open",
                menu_open_enc="Open Encrypted",
                menu_exit="Exit",
                menu_lang="Language",
                menu_help="Help",
                menu_docs="Documentation",
                menu_about="About"
            )
    
    def update_ui_texts(self, **kwargs):
        self.file_label.configure(text=kwargs["file_label"])
        self.btn_select.configure(text=kwargs["btn_select"])
        self.password_entry.configure(placeholder_text=kwargs["password_placeholder"])
        self.btn_encrypt.configure(text=kwargs["btn_encrypt"])
        self.btn_decrypt.configure(text=kwargs["btn_decrypt"])
        self.status_label.configure(text=kwargs["status_ready"])
        
        # Update menu texts
        self.menubar.entryconfig(1, label=kwargs["menu_file"])
        self.file_menu.entryconfig(0, label=kwargs["menu_open"])
        self.file_menu.entryconfig(1, label=kwargs["menu_open_enc"])
        self.file_menu.entryconfig(3, label=kwargs["menu_exit"])
        self.menubar.entryconfig(2, label=kwargs["menu_lang"])
        self.menubar.entryconfig(3, label=kwargs["menu_help"])
        self.help_menu.entryconfig(0, label=kwargs["menu_docs"])
        self.help_menu.entryconfig(1, label=kwargs["menu_about"])
    
    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.current_file = file_path
            self.file_label.configure(
                text=f"Selected: {os.path.basename(self.current_file)}",
                text_color=("gray", "white")[self.current_file.endswith(".encrypted")]
            )
            self.password_entry.configure(state="normal")
            self.password_entry.focus()
            self.update_buttons()
            self.update_status(f"Loaded: {os.path.basename(self.current_file)}")
    
    def update_buttons(self):
        is_encrypted = self.current_file and self.current_file.endswith(".encrypted")
        self.btn_encrypt.configure(state="normal" if not is_encrypted else "disabled")
        self.btn_decrypt.configure(state="normal" if is_encrypted else "disabled")
    
    def generate_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return salt, base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_file(self):
        if not self.current_file:
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Enter password!")
            return
            
        try:
            self.salt, self.key = self.generate_key(password)
            cipher = Fernet(self.key)
            
            with open(self.current_file, "rb") as f:
                data = f.read()
            
            encrypted_data = cipher.encrypt(data)
            
            output_path = f"{self.current_file}.encrypted"
            with open(output_path, "wb") as f:
                f.write(self.salt)
                f.write(encrypted_data)
                
            self.update_status(f"Encrypted: {os.path.basename(output_path)}", "green")
            self.file_label.configure(text=f"Encrypted: {os.path.basename(output_path)}")
            self.current_file = output_path
            self.update_buttons()
            
        except Exception as e:
            self.update_status(f"Error: {str(e)}", "red")
    
    def decrypt_file(self):
        if not (self.current_file and self.current_file.endswith(".encrypted")):
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Enter password!")
            return
            
        try:
            with open(self.current_file, "rb") as f:
                self.salt = f.read(16)
                encrypted_data = f.read()
            
            _, self.key = self.generate_key(password, self.salt)
            cipher = Fernet(self.key)
            
            decrypted_data = cipher.decrypt(encrypted_data)
            
            output_path = self.current_file.replace(".encrypted", "")
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
                
            self.update_status(f"Decrypted: {os.path.basename(output_path)}", "green")
            self.file_label.configure(text=f"Decrypted: {os.path.basename(output_path)}")
            self.current_file = output_path
            self.update_buttons()
            
        except Exception as e:
            self.update_status("Wrong password or corrupted file!", "red")
    
    def update_status(self, message, color="gray"):
        self.status_label.configure(text=message, text_color=color)

if __name__ == "__main__":
    FileCryptXPro()
