import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
import json
import tempfile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import uuid
import ctypes
from ctypes import wintypes
import shutil
import sys
import argparse
try:
    import tkinterdnd2
    HAS_DND = True
except ImportError:
    HAS_DND = False
    print("提示: 未安装tkinterdnd2库，拖拽功能不可用。请运行 'pip install tkinterdnd2' 启用拖拽功能。")


# ===============
# 加密解密功能
# ===============

class AESCipher:
    """
    AES加密解密类
    """
    
    def __init__(self, password):
        """
        初始化，根据密码生成密钥
        :param password: 用户提供的密码
        """
        # 使用SHA-256哈希函数将密码转换为32字节密钥（AES-256）
        # 对于AES-128，我们取前16字节
        self.key = hashlib.sha256(password.encode()).digest()[:16]
    
    def encrypt(self, plaintext):
        """
        加密数据
        :param plaintext: 待加密的数据
        :return: 加密后的数据 (bytes)
        """
        cipher = AES.new(self.key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        # 将IV（初始化向量）与加密数据一起返回
        return cipher.iv + ciphertext
    
    def decrypt(self, ciphertext):
        """
        解密数据
        :param ciphertext: 待解密的数据，包含IV和加密内容
        :return: 解密后的数据 (bytes)
        """
        # 提取IV（前16字节）
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        try:
            return unpad(decrypted_padded, AES.block_size)
        except ValueError as e:
            # 如果解密失败，可能是密码错误
            raise ValueError("密码错误或文件损坏") from e

def encrypt_file(file_path, password):
    """
    加密文件
    :param file_path: 文件路径
    :param password: 密码
    :return: 加密后文件路径
    """
    # 读取原始文件内容
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # 创建加密器
    cipher = AESCipher(password)
    
    # 加密数据
    encrypted_data = cipher.encrypt(file_data)
    
    # 创建Data目录（如果不存在）
    data_dir = os.path.join(os.path.dirname(__file__), 'Data')
    data_dir = os.path.abspath(data_dir)
    os.makedirs(data_dir, exist_ok=True)
    
    # 获取原文件名（不含路径）
    original_filename = os.path.basename(file_path)
    
    # 生成混淆的文件名
    encrypted_filename = str(uuid.uuid4()) + '.llaes'  # 使用.llaes扩展名
    encrypted_file_path = os.path.join(data_dir, encrypted_filename)
    
    # 写入加密文件
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    
    # 创建加密的元数据
    metadata = {
        "original_filename": original_filename,
        "original_filepath": file_path,  # 保留原始路径信息
        "encrypted_filename": encrypted_filename,
        "creation_time": time.time()
    }
    
    # 序列化元数据并加密
    metadata_json = json.dumps(metadata)
    encrypted_metadata = cipher.encrypt(metadata_json.encode('utf-8'))
    
    # 存储加密的元数据（使用与加密文件相同的UUID但不同扩展名）
    base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
    metadata_filename = base_uuid + '.meta'  # 使用.meta扩展名
    metadata_path = os.path.join(data_dir, metadata_filename)
    
    with open(metadata_path, 'wb') as f:
        f.write(encrypted_metadata)
    
    return encrypted_file_path

def decrypt_file(encrypted_file_path, password, output_dir=None, output_filename=None, delete_on_success=False):
    """
    解密文件
    :param encrypted_file_path: 加密文件路径
    :param password: 密码
    :param output_dir: 解密文件输出目录（可选，默认为当前目录）
    :param output_filename: 解密文件输出名称（可选，如果指定则使用该名称）
    :param delete_on_success: 解密成功后是否删除加密文件和元数据文件（可选，默认为False）
    :return: 解密后文件路径
    """
    # 读取加密文件内容
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # 创建解密器
    cipher = AESCipher(password)
    
    # 解密数据
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # 获取加密的元数据文件路径
    encrypted_filename = os.path.basename(encrypted_file_path)
    base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
    metadata_filename = base_uuid + '.meta'
    metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
    
    original_filename = None
    if os.path.exists(metadata_path):
        try:
            # 读取并解密元数据
            with open(metadata_path, 'rb') as f:
                encrypted_metadata = f.read()
            
            decrypted_metadata_bytes = cipher.decrypt(encrypted_metadata)
            decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
            metadata = json.loads(decrypted_metadata_json)
            
            original_filename = metadata.get("original_filename", None)
        except:
            # 如果解密元数据失败，仍然可以解密文件内容
            original_filename = None
    
    # 确定输出目录
    if output_dir is None:
        output_dir = os.getcwd()  # 使用当前工作目录
    
    # 确定输出文件名
    if output_filename:
        # 如果指定了输出文件名，使用指定的名称
        decrypted_file_path = os.path.join(output_dir, output_filename)
    elif original_filename:
        # 如果有原始文件名，则使用原始文件名
        decrypted_file_path = os.path.join(output_dir, original_filename)
        # 如果文件已存在，添加数字后缀
        counter = 1
        name, ext = os.path.splitext(decrypted_file_path)
        while os.path.exists(decrypted_file_path):
            decrypted_file_path = f"{name}_{counter}{ext}"
            counter += 1
    else:
        # 如果没有元数据，使用默认命名
        base_name = os.path.basename(encrypted_file_path).replace('.llaes', '')
        decrypted_filename = "decrypted_" + base_name + "_restored"
        decrypted_file_path = os.path.join(output_dir, decrypted_filename)
    
    # 写入解密文件
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    # 如果启用了成功后删除功能
    if delete_on_success:
        try:
            # 删除加密文件
            os.remove(encrypted_file_path)
            # 删除对应的元数据文件（如果存在）
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
        except Exception as e:
            print(f"删除文件时发生错误: {str(e)}")
    
    return decrypted_file_path

def get_available_memory():
    """
    获取系统可用内存大小（字节）
    """
    # 使用Windows API获取可用内存
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    memory_status = MEMORYSTATUSEX()
    memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    
    # 调用GlobalMemoryStatusEx函数
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status))
    
    # 返回可用物理内存大小（字节）
    return memory_status.ullAvailPhys

def get_encrypted_files_list(password):
    """
    获取Data目录中所有加密文件的列表
    :param password: 解密元数据所需的密码
    :return: 包含加密文件信息的列表
    """
    data_dir = os.path.join(os.path.dirname(__file__), 'Data')
    data_dir = os.path.abspath(data_dir)
    
    if not os.path.exists(data_dir):
        return []
    
    encrypted_files = []
    
    # 创建解密器用于解密元数据
    cipher = AESCipher(password)
    
    for filename in os.listdir(data_dir):
        if filename.endswith('.llaes'):
            encrypted_file_path = os.path.join(data_dir, filename)
            
            # 获取对应元数据文件
            base_uuid = os.path.splitext(filename)[0]  # 获取UUID部分
            metadata_filename = base_uuid + '.meta'
            metadata_path = os.path.join(data_dir, metadata_filename)
            
            original_filename = "未知文件"
            
            if os.path.exists(metadata_path):
                try:
                    # 读取加密的元数据
                    with open(metadata_path, 'rb') as f:
                        encrypted_metadata = f.read()
                    
                    # 解密元数据
                    decrypted_metadata_bytes = cipher.decrypt(encrypted_metadata)
                    decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                    metadata = json.loads(decrypted_metadata_json)
                    
                    original_filename = metadata.get("original_filename", "未知文件")
                except:
                    # 如果解密元数据失败，仍显示为未知文件
                    original_filename = "未知文件 (元数据解密失败)"
            
            # 获取文件大小
            file_size = os.path.getsize(encrypted_file_path)
            
            # 获取修改时间
            mod_time = os.path.getmtime(encrypted_file_path)
            
            encrypted_files.append({
                "encrypted_path": encrypted_file_path,
                "original_name": original_filename,
                "encrypted_name": filename,
                "size": file_size,
                "mod_time": mod_time
            })
    
    return encrypted_files

def view_encrypted_file(encrypted_file_path, password):
    """
    查看加密文件内容（解密后以文本形式返回）
    :param encrypted_file_path: 加密文件路径
    :param password: 密码
    :return: 解密后的文本内容
    """
    try:
        # 读取加密文件内容
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 创建解密器
        cipher = AESCipher(password)
        
        # 解密数据
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 检查是否需要使用临时文件
        available_memory = get_available_memory()
        min_memory_threshold = 1024 * 1024 * 1024  # 1GB
        
        if available_memory < min_memory_threshold:
            # 内存不足，使用临时文件
            # 创建临时文件来存储解密数据
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
                temp_file.write(decrypted_data)
                temp_file_path = temp_file.name
            
            # 读取临时文件内容
            try:
                with open(temp_file_path, 'rb') as temp_file:
                    content = temp_file.read()
                try:
                    result = content.decode('utf-8')
                except UnicodeDecodeError:
                    result = "无法以文本形式显示文件内容，文件可能是二进制格式。"
            finally:
                # 删除临时文件
                os.unlink(temp_file_path)
        else:
            # 内存充足，直接在内存中处理
            try:
                result = decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                result = "无法以文本形式显示文件内容，文件可能是二进制格式。"
        
        return result
    except ValueError as e:
        return f"密码错误或文件损坏：{str(e)}"
    except Exception as e:
        return f"解密失败: {str(e)}"


# ===============
# 配置管理功能
# ===============

# 配置文件路径
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

def load_config():
    """
    加载配置
    """
    default_config = {
        "show_version": True,  # 默认显示版本号
        "copy_encrypted_file": False  # 默认复制解密后的文件
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # 确保配置包含所有必需的键
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except Exception:
            pass  # 如果配置文件损坏，使用默认配置
    
    return default_config

def save_config(config):
    """
    保存配置
    """
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"保存配置失败: {e}")
        return False

# ===============
# 密码管理功能
# ===============

# Data目录路径
DATA_DIR = os.path.join(os.path.dirname(__file__), 'Data')
DATA_DIR = os.path.abspath(DATA_DIR)

# 加密密码文件名（固定名称，但内容加密）
ENCRYPTED_PASSWORD_FILE = os.path.join(DATA_DIR, 'master_pwd.dat')

def _get_key_from_password(password):
    """根据密码生成加密密钥"""
    # 使用SHA-256哈希函数将密码转换为32字节密钥
    return hashlib.sha256(password.encode()).digest()

def _encrypt_data(data, password):
    """加密数据"""
    key = _get_key_from_password(password)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    # 将IV与加密数据一起返回
    return cipher.iv + encrypted_data

def _decrypt_data(encrypted_data, password):
    """解密数据"""
    key = _get_key_from_password(password)
    # 提取IV（前16字节）
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_content)
    return unpad(decrypted_padded, AES.block_size).decode('utf-8')

def save_password(password):
    """
    保存加密的密码哈希
    """
    # 使用SHA256创建密码哈希
    from Crypto.Hash import SHA256
    hasher = SHA256.new()
    hasher.update(password.encode('utf-8'))
    password_hash = hasher.hexdigest()
    
    # 准备要加密的数据
    data_to_encrypt = json.dumps({"password_hash": password_hash})
    
    # 加密密码数据
    encrypted_data = _encrypt_data(data_to_encrypt, password)
    
    # 创建Data目录（如果不存在）
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 生成混淆的文件名
    encrypted_filename = str(uuid.uuid4()) + '.pwd'  # 使用.pwd扩展名标识密码文件
    global ENCRYPTED_PASSWORD_FILE
    ENCRYPTED_PASSWORD_FILE = os.path.join(DATA_DIR, encrypted_filename)
    
    # 保存加密的密码数据
    with open(ENCRYPTED_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_data)
    
    # 创建一个元数据文件，记录密码文件的真实名称（也加密存储）
    metadata = {"filename": encrypted_filename}
    metadata_json = json.dumps(metadata)
    encrypted_metadata = _encrypt_data(metadata_json, password)
    
    metadata_filename = str(uuid.uuid4()) + '.meta'
    metadata_path = os.path.join(DATA_DIR, metadata_filename)
    
    with open(metadata_path, 'wb') as f:
        f.write(encrypted_metadata)

def verify_password(input_password):
    """
    验证输入的密码是否正确
    """
    global ENCRYPTED_PASSWORD_FILE
    
    # 首先需要找到密码文件（通过查找.meta文件确定密码文件名）
    if os.path.exists(DATA_DIR):
        for filename in os.listdir(DATA_DIR):
            if filename.endswith('.meta'):
                meta_path = os.path.join(DATA_DIR, filename)
                try:
                    # 尝试用输入的密码解密元数据以找到密码文件
                    with open(meta_path, 'rb') as f:
                        encrypted_meta = f.read()
                    
                    decrypted_meta_json = _decrypt_data(encrypted_meta, input_password)
                    meta_data = json.loads(decrypted_meta_json)
                    
                    # 如果成功解密元数据，那么找到了正确的密码
                    actual_pwd_filename = meta_data.get("filename")
                    if actual_pwd_filename:
                        ENCRYPTED_PASSWORD_FILE = os.path.join(DATA_DIR, actual_pwd_filename)
                        
                        # 现在尝试解密密码文件
                        with open(ENCRYPTED_PASSWORD_FILE, 'rb') as f:
                            encrypted_pwd = f.read()
                        
                        decrypted_pwd_json = _decrypt_data(encrypted_pwd, input_password)
                        pwd_data = json.loads(decrypted_pwd_json)
                        
                        # 使用SHA256创建输入密码的哈希
                        from Crypto.Hash import SHA256
                        hasher = SHA256.new()
                        hasher.update(input_password.encode('utf-8'))
                        input_hash = hasher.hexdigest()
                        
                        # 比较哈希值
                        return input_hash == pwd_data["password_hash"]
                except:
                    # 如果解密失败，继续尝试其他.meta文件
                    continue
    
    return False

def is_password_set():
    """
    检查是否已经设置了密码
    """
    # 检查Data目录中是否存在.meta文件，这通常意味着设置了密码
    # 但是我们还需要验证对应的密码文件是否也存在
    if os.path.exists(DATA_DIR):
        meta_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.meta')]
        if meta_files:
            # 如果存在.meta文件，尝试用其中一个解密，看是否能找到对应的密码文件
            for meta_filename in meta_files:
                meta_path = os.path.join(DATA_DIR, meta_filename)
                try:
                    # 尝试用一个假密码解密meta文件，看是否能获得密码文件名
                    # 这需要尝试解密来判断密码文件是否仍然存在
                    with open(meta_path, 'rb') as f:
                        encrypted_meta = f.read()
                    
                    # 尝试用一个随机密码来解密meta文件，如果能解密成功得到密码文件名，
                    # 但找不到对应的密码文件，则说明密码文件被删除了
                    # 但更简单的方法是尝试验证一个假密码，如果失败但有meta文件存在，
                    # 再检查是否存在对应的密码文件
                    return len([f for f in os.listdir(DATA_DIR) if f.endswith('.pwd')]) > 0
                except:
                    continue
    return False

def clear_data_folder():
    """
    清空Data文件夹内的所有文件
    """
    if os.path.exists(DATA_DIR):
        for filename in os.listdir(DATA_DIR):
            file_path = os.path.join(DATA_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"删除文件 {file_path} 时发生错误: {e}")

class PasswordSetupApp:
    """
    密码设置界面
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("设置主密码")
        self.root.geometry("400x200")
        self.setup_ui()
    
    def setup_ui(self):
        """
        设置用户界面
        """
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="请设置主密码", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 密码输入
        ttk.Label(main_frame, text="设置密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=25)
        self.password_entry.grid(row=1, column=1, pady=5)
        
        # 确认密码
        ttk.Label(main_frame, text="确认密码:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(main_frame, textvariable=self.confirm_password_var, show="*", width=25)
        self.confirm_password_entry.grid(row=2, column=1, pady=5)
        
        # 按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="确定", command=self.set_password).grid(row=0, column=0, padx=5)
    
    def set_password(self):
        """
        设置密码
        """
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
        if not password:
            messagebox.showerror("错误", "请输入密码")
            return
        
        if password != confirm_password:
            messagebox.showerror("错误", "两次输入的密码不一致")
            return
        
        if len(password) < 6:
            messagebox.showerror("错误", "密码长度至少为6位")
            return
        
        try:
            # 保存密码
            save_password(password)
            messagebox.showinfo("成功", "密码设置成功！")
            # 关闭设置窗口并打开主程序
            self.root.destroy()
            if HAS_DND:
                 main_app_root = tkinterdnd2.Tk()
            else:
                 main_app_root = tk.Tk()
            app = FileEncryptionApp(main_app_root, password)  # 传递主密码
            main_app_root.mainloop()
        except Exception as e:
            messagebox.showerror("错误", f"设置密码时发生错误: {str(e)}")

class PasswordVerificationApp:
    """
    密码验证界面
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("验证主密码")
        self.root.geometry("400x150")
        self.setup_ui()
    
    def setup_ui(self):
        """
        设置用户界面
        """
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="请输入主密码", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 密码输入
        ttk.Label(main_frame, text="密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=25)
        self.password_entry.grid(row=1, column=1, pady=5)
        self.password_entry.bind('<Return>', lambda event: self.verify_password())  # 回车键确认
        
        # 按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="确定", command=self.verify_password).grid(row=0, column=0, padx=5)
        
        # 设置焦点到密码输入框
        self.password_entry.focus()

    def verify_password(self):
        """
        验证密码
        """
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("错误", "请输入密码")
            return
        
        if verify_password(password):
            messagebox.showinfo("成功", "密码验证成功！")
            # 关闭验证窗口并打开主程序
            self.root.destroy()
            if HAS_DND:
                 main_app_root = tkinterdnd2.Tk()
            else:
                 main_app_root = tk.Tk()
            app = FileEncryptionApp(main_app_root, password)  # 传递主密码
            main_app_root.mainloop()
        else:
            messagebox.showerror("错误", "密码错误，请重试")
            self.password_var.set("")  # 清空输入框
            self.password_entry.focus()  # 重新聚焦到输入框

class FileEncryptionApp:
    """
    文件加密软件主界面
    """
    
    def __init__(self, root, master_password):
        # 存储根窗口和主密码
        self.root = root
        self.master_password = master_password
        
        self.root.title("AES-128文件加密器")
        self.root.geometry("800x600")
        
        # 加载配置
        self.config = load_config()
        
        # 当前选中的加密文件
        self.selected_encrypted_file = None
        
        # 添加拖拽事件（如果支持）
        if HAS_DND:
            # 假设 root 是 tkinterdnd2.Tk 类型或者兼容 DnD
            # 注意：这里需要确保 root 是由 tkinterdnd2.Tk() 创建的
            self.root.drop_target_register(tkinterdnd2.DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.on_drop)
        
        self.setup_ui()
        # 根据配置设置版本号显示
        self.update_version_label_visibility()
        # 刷新文件列表
        self.refresh_file_list()
    
    def setup_ui(self):
        """
        设置用户界面
        """
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="AES-128文件加密器", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=4, pady=10)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=5)

        # 添加文件按钮
        self.add_file_btn = ttk.Button(button_frame, text="添加文件", command=self.add_file)
        self.add_file_btn.grid(row=0, column=0, padx=5)

        # 解密按钮
        self.decrypt_btn = ttk.Button(button_frame, text="解密文件", command=self.decrypt_selected_file)
        self.decrypt_btn.grid(row=0, column=1, padx=5)

        # 查看加密文件内容按钮
        self.view_btn = ttk.Button(button_frame, text="查看内容", command=self.view_selected_file)
        self.view_btn.grid(row=0, column=2, padx=5)

        # 刷新列表按钮
        self.refresh_btn = ttk.Button(button_frame, text="刷新列表", command=self.refresh_file_list)
        self.refresh_btn.grid(row=0, column=3, padx=5)
        
        # 设置按钮，靠右对齐
        self.settings_btn = ttk.Button(button_frame, text="设置", command=self.open_settings)
        self.settings_btn.grid(row=0, column=4, padx=5, sticky="e")

        # 创建文件列表区域
        list_frame = ttk.LabelFrame(main_frame, text="加密文件列表", padding="5")
        list_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # 创建文件列表
        columns = ("原文件名", "加密文件名", "大小", "修改时间")
        self.file_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)

        # 设置列标题
        self.file_tree.heading("原文件名", text="原文件名")
        self.file_tree.heading("加密文件名", text="加密文件名")
        self.file_tree.heading("大小", text="大小")
        self.file_tree.heading("修改时间", text="修改时间")

        # 设置列宽
        self.file_tree.column("原文件名", width=150)
        self.file_tree.column("加密文件名", width=150)
        self.file_tree.column("大小", width=100)
        self.file_tree.column("修改时间", width=150)

        # 滚动条
        tree_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)

        self.file_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # 绑定选择事件
        self.file_tree.bind("<<TreeviewSelect>>", self.on_file_select)
        
        # 绑定右键单击事件以显示上下文菜单
        self.file_tree.bind("<Button-3>", self.show_context_menu)  # Button-3 代表右键

        # 配置列表框架的权重
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        # 结果显示区域
        ttk.Label(main_frame, text="操作结果:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        self.result_text = scrolledtext.ScrolledText(main_frame, width=90, height=12)
        self.result_text.grid(row=4, column=0, columnspan=4, pady=5)

        # 配置主框架权重以支持窗口缩放
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)  # 文件列表行可扩展
        main_frame.rowconfigure(4, weight=1)  # 结果区域行可扩展

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # 设置按钮靠右对齐
        button_frame.columnconfigure(0, weight=1)  # 给第一个按钮左边留出空间

        # 添加拖拽功能提示标签（如果支持拖拽）
        if HAS_DND:
            dnd_label = ttk.Label(main_frame, text="提示: 您可以直接将文件拖拽到此窗口进行加密", 
                                 font=("Arial", 9), foreground="blue")
            dnd_label.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), padx=5, pady=5)
        else:
            dnd_label = ttk.Label(main_frame, text="提示: 安装tkinterdnd2库以启用拖拽加密功能", 
                                 font=("Arial", 9), foreground="orange")
            dnd_label.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), padx=5, pady=5)

        # 添加版权信息和版本号框架
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 添加版权信息标签
        copyright_label = ttk.Label(bottom_frame, text="AES128OnPython 许可证基于MIT", 
                                   font=("Arial", 8), foreground="gray")
        copyright_label.grid(row=0, column=0, sticky=tk.W)
        
        # 添加版本号标签 (V2.4-beta1)
        self.version_label = ttk.Label(bottom_frame, text="V2.4-beta1", 
                                      font=("Arial", 8), foreground="gray")
        self.version_label.grid(row=0, column=1, sticky=tk.E)
        
        # 配置bottom_frame列权重，使版权信息扩展，版本号靠右
        bottom_frame.columnconfigure(0, weight=1)

        # 配置main_frame行权重，确保底部标签显示
        main_frame.rowconfigure(6, weight=0)  # 版权信息和版本号行不扩展
    
    def update_version_label_visibility(self):
        """
        根据配置更新版本号标签的可见性
        """
        if self.config.get("show_version", True):
            # 显示版本号 - 使用sticky使标签正确对齐
            self.version_label.grid(row=0, column=1, sticky=tk.E)
        else:
            # 隐藏版本号
            self.version_label.grid_remove()
    
    def toggle_version_display(self, show_version):
        """
        切换版本号显示
        """
        # 更新配置
        self.config["show_version"] = show_version
        # 保存配置到文件
        save_config(self.config)
        # 更新界面
        self.update_version_label_visibility()
    
    def toggle_copy_encrypted_setting(self, copy_encrypted):
        """
        切换复制加密文件设置
        """
        # 更新配置
        self.config["copy_encrypted_file"] = copy_encrypted
        # 保存配置到文件
        save_config(self.config)
    
    def show_context_menu(self, event):
        """
        显示右键菜单
        """
        # 获取右键点击位置的项目
        item_id = self.file_tree.identify_row(event.y)
        if item_id:
            # 选中该项目，以便删除操作作用于正确的文件
            self.file_tree.selection_set(item_id)
            self.on_file_select(None)  # 更新 self.selected_encrypted_file

            # 创建上下文菜单
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="复制文件", command=self.copy_selected_file)
            context_menu.add_command(label="删除文件", command=self.delete_selected_file)

            # 在鼠标位置显示菜单
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()  # 确保菜单在点击后消失

    def copy_selected_file(self):
        """
        复制选中的加密文件到剪贴板
        根据配置决定复制加密文件还是解密后的文件
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return

        try:
            # 根据配置决定复制加密文件还是解密后的文件
            if self.config.get("copy_encrypted_file", False):
                # 复制加密文件
                self.copy_encrypted_file_to_clipboard(self.selected_encrypted_file)
            else:
                # 复制解密后的文件
                self.copy_decrypted_file_to_clipboard(self.selected_encrypted_file)
        except Exception as e:
            messagebox.showerror("复制失败", f"复制文件时发生错误: {str(e)}")
    
    def copy_encrypted_file_to_clipboard(self, encrypted_file_path):
        """
        将加密文件复制到Windows剪贴板
        """
        try:
            # 创建临时文件来存放加密文件的副本
            filename = os.path.basename(encrypted_file_path)
            import tempfile
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, filename)
            
            # 为临时文件名添加唯一性，以防重名
            counter = 1
            original_temp_path = temp_path
            while os.path.exists(temp_path):
                name, ext = os.path.splitext(original_temp_path)
                temp_path = f"{name}_{counter}{ext}"
                counter += 1
            
            # 复制加密文件到临时位置
            shutil.copy2(encrypted_file_path, temp_path)
            
            # 调用外部命令将文件路径写入剪贴板（在Windows上）
            import subprocess
            
            # 创建一个包含文件路径的临时文件
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(temp_path)
                temp_list_file = f.name
            
            # 使用PowerShell命令将文件路径放入剪贴板
            try:
                # 在PowerShell中执行将文件路径列表放入剪贴板的命令
                ps_command = f'Get-Content "{temp_list_file}" | Set-Clipboard'
                subprocess.run(['powershell', '-Command', ps_command], check=True)
                
                # 同时执行将文件本身放入剪贴板的特殊命令
                # 使用PowerShell和COM对象将文件路径放入剪贴板
                ps_script = f'''
                Add-Type -AssemblyName System.Windows.Forms
                $fileDropList = New-Object System.Collections.Specialized.StringCollection
                $fileDropList.Add('{temp_path.replace(os.sep, "/")}')
                [System.Windows.Forms.Clipboard]::SetFileDropList($fileDropList)
                '''
                subprocess.run(['powershell', '-Command', ps_script], check=True, capture_output=True)
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"已将加密文件复制到剪贴板: {filename}\\n")
                messagebox.showinfo("成功", f"已将加密文件复制到剪贴板: {filename}")
            except subprocess.CalledProcessError:
                # 如果PowerShell方法失败，使用另一种方法
                # 使用系统命令行将路径复制到剪贴板
                os.system(f'echo {temp_path} | clip')
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"已将加密文件路径复制到剪贴板: {filename}\\n（使用备选方法）")
                messagebox.showinfo("成功", f"已将加密文件路径复制到剪贴板: {filename}")
            finally:
                # 清理临时文件
                try:
                    os.unlink(temp_list_file)
                except:
                    pass
            
        except Exception as e:
            messagebox.showerror("复制失败", f"复制加密文件时发生错误: {str(e)}")
    
    def copy_decrypted_file_to_clipboard(self, encrypted_file_path):
        """
        将解密后的文件复制到Windows剪贴板
        """
        try:
            # 解密文件到临时位置
            import tempfile
            temp_dir = tempfile.gettempdir()
            
            # 获取原始文件名（如果可能）
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            cipher = AESCipher(self.master_password)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # 获取原始文件名（从元数据中）
            encrypted_filename = os.path.basename(encrypted_file_path)
            base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
            metadata_filename = base_uuid + '.meta'
            metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
            
            original_filename = "decrypted_file"
            if os.path.exists(metadata_path):
                try:
                    # 读取并解密元数据
                    with open(metadata_path, 'rb') as f:
                        encrypted_metadata = f.read()
                    
                    decrypted_metadata_bytes = cipher.decrypt(encrypted_metadata)
                    decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                    metadata = json.loads(decrypted_metadata_json)
                    
                    original_filename = metadata.get("original_filename", "decrypted_file")
                except:
                    original_filename = "decrypted_file"
            
            # 创建临时文件来存放解密文件的副本
            temp_path = os.path.join(temp_dir, original_filename)
            
            # 为临时文件名添加唯一性，以防重名
            counter = 1
            original_temp_path = temp_path
            while os.path.exists(temp_path):
                name, ext = os.path.splitext(original_temp_path)
                temp_path = f"{name}_{counter}{ext}"
                counter += 1
            
            # 将解密数据写入临时位置
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
            
            # 调用外部命令将文件路径写入剪贴板（在Windows上）
            import subprocess
            
            # 创建一个包含文件路径的临时文件
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(temp_path)
                temp_list_file = f.name
            
            # 使用PowerShell命令将文件路径放入剪贴板
            try:
                # 在PowerShell中执行将文件路径列表放入剪贴板的命令
                ps_command = f'Get-Content "{temp_list_file}" | Set-Clipboard'
                subprocess.run(['powershell', '-Command', ps_command], check=True)
                
                # 同时执行将文件本身放入剪贴板的特殊命令
                # 使用PowerShell和COM对象将文件路径放入剪贴板
                ps_script = f'''
                Add-Type -AssemblyName System.Windows.Forms
                $fileDropList = New-Object System.Collections.Specialized.StringCollection
                $fileDropList.Add('{temp_path.replace(os.sep, "/")}')
                [System.Windows.Forms.Clipboard]::SetFileDropList($fileDropList)
                '''
                subprocess.run(['powershell', '-Command', ps_script], check=True, capture_output=True)
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"已将解密文件复制到剪贴板: {original_filename}\\n")
                messagebox.showinfo("成功", f"已将解密文件复制到剪贴板: {original_filename}")
            except subprocess.CalledProcessError:
                # 如果PowerShell方法失败，使用另一种方法
                # 使用系统命令行将路径复制到剪贴板
                os.system(f'echo {temp_path} | clip')
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"已将解密文件路径复制到剪贴板: {original_filename}\\n（使用备选方法）")
                messagebox.showinfo("成功", f"已将解密文件路径复制到剪贴板: {original_filename}")
            finally:
                # 清理临时文件
                try:
                    os.unlink(temp_list_file)
                except:
                    pass
            
        except Exception as e:
            messagebox.showerror("复制失败", f"复制解密文件时发生错误: {str(e)}")

    def add_file(self):
        """
        添加文件进行加密
        """
        file_paths = filedialog.askopenfilenames(title="选择要加密的文件")
        
        if not file_paths:
            return
        
        success_count = 0
        for file_path in file_paths:
            try:
                encrypted_path = encrypt_file(file_path, self.master_password)
                self.result_text.insert(tk.END, f"文件加密成功: {file_path} -> {encrypted_path}\\n")
                success_count += 1
            except Exception as e:
                self.result_text.insert(tk.END, f"文件加密失败 {file_path}: {str(e)}\\n")
        
        self.result_text.see(tk.END)
        messagebox.showinfo("完成", f"已处理 {len(file_paths)} 个文件，其中 {success_count} 个加密成功")
        
        # 刷新文件列表
        self.refresh_file_list()

    def decrypt_selected_file(self):
        """
        解密选中的文件
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return

        # 询问输出目录
        output_dir = filedialog.askdirectory(title="选择解密文件保存目录")
        if not output_dir:
            return

        try:
            # 解密文件
            decrypted_path = decrypt_file(self.selected_encrypted_file, self.master_password, output_dir=output_dir)
            
            # 显示结果
            self.result_text.insert(tk.END, f"文件解密成功: {self.selected_encrypted_file} -> {decrypted_path}\\n")
            self.result_text.see(tk.END)
            
            messagebox.showinfo("成功", f"文件解密成功！\\n解密后文件路径: {decrypted_path}")
        except ValueError as e:
            # 密码错误
            messagebox.showerror("解密失败", f"密码错误或文件损坏: {str(e)}")
        except Exception as e:
            messagebox.showerror("解密失败", f"解密过程中发生错误: {str(e)}")

    def on_file_select(self, event):
        """
        处理文件选择事件
        """
        selection = self.file_tree.selection()
        if selection:
            item = self.file_tree.item(selection[0])
            # 获取加密文件路径
            encrypted_filename = item['values'][1]  # 加密文件名在第二列
            data_dir = os.path.join(os.path.dirname(__file__), 'Data')
            self.selected_encrypted_file = os.path.join(data_dir, encrypted_filename)
        else:
            self.selected_encrypted_file = None

    def refresh_file_list(self):
        """
        刷新加密文件列表
        """
        # 清空现有项目
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        try:
            # 获取加密文件列表
            encrypted_files = get_encrypted_files_list(self.master_password)
            
            # 添加到树视图
            for file_info in encrypted_files:
                # 格式化文件大小
                size_str = f"{file_info['size']} 字节"
                if file_info['size'] > 1024:
                    size_str = f"{file_info['size']/1024:.2f} KB"
                if file_info['size'] > 1024*1024:
                    size_str = f"{file_info['size']/(1024*1024):.2f} MB"
                
                # 格式化修改时间
                mod_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_info['mod_time']))
                
                self.file_tree.insert('', 'end', values=(
                    file_info['original_name'],
                    file_info['encrypted_name'],
                    size_str,
                    mod_time_str
                ))
        except Exception as e:
            messagebox.showerror("错误", f"刷新文件列表时发生错误: {str(e)}")

    def view_selected_file(self):
        """
        查看选中的加密文件内容
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return

        try:
            content = view_encrypted_file(self.selected_encrypted_file, self.master_password)
            
            # 创建新窗口显示内容
            view_window = tk.Toplevel(self.root)
            view_window.title(f"查看文件内容 - {os.path.basename(self.selected_encrypted_file)}")
            view_window.geometry("600x400")
            
            # 创建文本区域
            text_area = scrolledtext.ScrolledText(view_window, wrap=tk.WORD)
            text_area.pack(expand=True, fill='both', padx=10, pady=10)
            
            # 插入内容
            text_area.insert(tk.END, content)
            text_area.config(state=tk.DISABLED)  # 设置为只读
            
        except Exception as e:
            messagebox.showerror("查看失败", f"查看文件内容时发生错误: {str(e)}")

    def delete_selected_file(self):
        """
        删除选中的加密文件及其元数据
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return

        if messagebox.askyesno("确认删除", f"确定要删除加密文件吗？\\n{self.selected_encrypted_file}"):
            try:
                # 删除加密文件
                os.remove(self.selected_encrypted_file)
                
                # 删除对应的元数据文件
                encrypted_filename = os.path.basename(self.selected_encrypted_file)
                base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
                metadata_filename = base_uuid + '.meta'
                metadata_path = os.path.join(os.path.dirname(self.selected_encrypted_file), metadata_filename)
                
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
                
                # 删除对应的密码文件（如果存在，且没有其他文件依赖它）
                pwd_filename = base_uuid + '.pwd'
                pwd_path = os.path.join(os.path.dirname(self.selected_encrypted_file), pwd_filename)
                
                if os.path.exists(pwd_path):
                    os.remove(pwd_path)
                
                self.result_text.insert(tk.END, f"已删除文件: {self.selected_encrypted_file}\\n")
                self.result_text.see(tk.END)
                
                # 从列表中移除该项目
                for item in self.file_tree.get_children():
                    values = self.file_tree.item(item)['values']
                    if values[1] == encrypted_filename:  # 根据加密文件名匹配
                        self.file_tree.delete(item)
                        break
                
                messagebox.showinfo("成功", "文件已删除")
            except Exception as e:
                messagebox.showerror("删除失败", f"删除文件时发生错误: {str(e)}")

    def on_drop(self, event):
        """
        处理文件拖拽事件
        """
        if HAS_DND:
            # 获取拖拽的文件路径
            files = self.root.tk.splitlist(event.data)
            
            success_count = 0
            for file_path in files:
                try:
                    # 确保路径是有效的文件
                    if os.path.isfile(file_path):
                        encrypted_path = encrypt_file(file_path, self.master_password)
                        self.result_text.insert(tk.END, f"文件加密成功: {file_path} -> {encrypted_path}\\n")
                        success_count += 1
                except Exception as e:
                    self.result_text.insert(tk.END, f"文件加密失败 {file_path}: {str(e)}\\n")
            
            self.result_text.see(tk.END)
            messagebox.showinfo("完成", f"已处理 {len(files)} 个拖拽的文件，其中 {success_count} 个加密成功")
            
            # 刷新文件列表
            self.refresh_file_list()

    def open_settings(self):
        """
        打开设置窗口
        """
        settings_window = tk.Toplevel(self.root)
        settings_window.title("设置")
        settings_window.geometry("300x300")
        
        main_frame = ttk.Frame(settings_window, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="设置", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 版本号显示开关
        show_version_var = tk.BooleanVar(value=self.config.get("show_version", True))
        version_checkbox = ttk.Checkbutton(
            main_frame, 
            text="显示版本号", 
            variable=show_version_var,
            command=lambda: self.toggle_version_display(show_version_var.get())
        )
        version_checkbox.grid(row=1, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        # 复制加密文件开关
        copy_encrypted_var = tk.BooleanVar(value=self.config.get("copy_encrypted_file", False))
        copy_encrypted_checkbox = ttk.Checkbutton(
            main_frame, 
            text="复制加密文件（否则复制解密文件）", 
            variable=copy_encrypted_var,
            command=lambda: self.toggle_copy_encrypted_setting(copy_encrypted_var.get())
        )
        copy_encrypted_checkbox.grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        # 修改密码按钮
        change_password_btn = ttk.Button(main_frame, text="修改密码", command=lambda: self.open_change_password(settings_window))
        change_password_btn.grid(row=3, column=0, columnspan=2, pady=10)
    
    def open_change_password(self, parent_window):
        """
        打开修改密码窗口
        """
        change_window = tk.Toplevel(parent_window)
        change_window.title("修改密码")
        change_window.geometry("400x300")
        
        main_frame = ttk.Frame(change_window, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="修改密码", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 旧密码输入
        ttk.Label(main_frame, text="旧密码").grid(row=1, column=0, sticky=tk.W, pady=5)
        old_password_var = tk.StringVar()
        old_password_entry = ttk.Entry(main_frame, textvariable=old_password_var, show="*", width=25)
        old_password_entry.grid(row=1, column=1, pady=5)
        
        # 新密码输入
        ttk.Label(main_frame, text="新密码").grid(row=2, column=0, sticky=tk.W, pady=5)
        new_password_var = tk.StringVar()
        new_password_entry = ttk.Entry(main_frame, textvariable=new_password_var, show="*", width=25)
        new_password_entry.grid(row=2, column=1, pady=5)
        
        # 确认新密码
        ttk.Label(main_frame, text="确认新密码").grid(row=3, column=0, sticky=tk.W, pady=5)
        confirm_new_password_var = tk.StringVar()
        confirm_new_password_entry = ttk.Entry(main_frame, textvariable=confirm_new_password_var, show="*", width=25)
        confirm_new_password_entry.grid(row=3, column=1, pady=5)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        # 确认按钮
        ttk.Button(button_frame, text="确认", command=lambda: self.change_password(
            old_password_var.get(), 
            new_password_var.get(), 
            confirm_new_password_var.get(), 
            change_window, 
            parent_window
        )).grid(row=0, column=0, padx=5)
        
        # 取消按钮
        ttk.Button(button_frame, text="取消", command=change_window.destroy).grid(row=0, column=1, padx=5)
    
    def change_password(self, old_password, new_password, confirm_new_password, change_window, parent_window):
        """
        修改密码
        """
        # 验证旧密码是否正确
        if not verify_password(old_password):
            messagebox.showerror("错误", "旧密码错误")
            return
        
        # 验证新密码
        if not new_password:
            messagebox.showerror("错误", "请输入新密码")
            return
        
        if new_password != confirm_new_password:
            messagebox.showerror("错误", "两次输入的新密码不一致")
            return
        
        if len(new_password) < 6:
            messagebox.showerror("错误", "密码长度至少为6位")
            return
        
        # --- NEW: Find old password and meta file names BEFORE saving new password ---
        old_pwd_path = None
        old_meta_path = None

        # Iterate through .meta files in DATA_DIR, try to decrypt each with old password
        for filename in os.listdir(DATA_DIR):
            if filename.endswith('.meta'):
                meta_path = os.path.join(DATA_DIR, filename)
                try:
                    with open(meta_path, 'rb') as f:
                        encrypted_meta = f.read()

                    # Try to decrypt the meta file with the old password
                    decrypted_meta_json = _decrypt_data(encrypted_meta, old_password)
                    meta_data = json.loads(decrypted_meta_json)

                    # If decryption is successful, we found the correct meta file and pwd file name
                    actual_pwd_filename = meta_data.get("filename")
                    if actual_pwd_filename:
                        pwd_path = os.path.join(DATA_DIR, actual_pwd_filename)
                        # Verify that the corresponding .pwd file also exists
                        if os.path.exists(pwd_path):
                            old_pwd_path = pwd_path
                            old_meta_path = meta_path
                            # We have found the old files, break the loop
                            break
                except Exception:
                    # If decryption fails, continue to the next .meta file
                    continue

        # Check if we found the old files
        if not old_pwd_path or not old_meta_path:
            messagebox.showerror("错误", "无法定位旧的密码文件，可能存在数据损坏。")
            return
        # --- END NEW ---

        try:
            # 获取所有加密文件的列表
            encrypted_files = get_encrypted_files_list(old_password)
            
            # 使用新密码保存密码(this creates new .pwd and .meta files)
            save_password(new_password)
            
            # Update the main password
            self.master_password = new_password
            
            # 重新加密所有文件
            for file_info in encrypted_files:
                encrypted_file_path = file_info['encrypted_path']
                
                # 解密原始文件内容
                with open(encrypted_file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                old_cipher = AESCipher(old_password)
                decrypted_data = old_cipher.decrypt(encrypted_data)
                
                # 获取对应的元数据文件路径
                encrypted_filename = os.path.basename(encrypted_file_path)
                base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
                metadata_filename = base_uuid + '.meta'
                metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
                
                original_filename = None
                original_filepath = None
                creation_time = time.time()
                
                if os.path.exists(metadata_path):
                    try:
                        # 读取并解密元数据
                        with open(metadata_path, 'rb') as f:
                            encrypted_metadata = f.read()
                        
                        decrypted_metadata_bytes = old_cipher.decrypt(encrypted_metadata)
                        decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                        metadata = json.loads(decrypted_metadata_json)
                        
                        original_filename = metadata.get("original_filename", None)
                        original_filepath = metadata.get("original_filepath", None)
                        creation_time = metadata.get("creation_time", time.time())
                    except:
                        # 如果解密元数据失败，仍然可以继续重新加密文件内容
                        pass
                
                # 使用新密码加密文件内容
                new_cipher = AESCipher(new_password)
                new_encrypted_data = new_cipher.encrypt(decrypted_data)
                
                # 生成新的混淆的文件名
                new_encrypted_filename = str(uuid.uuid4()) + '.llaes'
                new_encrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), new_encrypted_filename)
                
                # 写入新的加密文件
                with open(new_encrypted_file_path, 'wb') as f:
                    f.write(new_encrypted_data)
                
                # 创建新的加密元数据
                new_metadata = {
                    "original_filename": original_filename or file_info['original_name'],
                    "original_filepath": original_filepath,
                    "encrypted_filename": new_encrypted_filename,
                    "creation_time": creation_time
                }
                
                # 序列化新元数据并加密
                new_metadata_json = json.dumps(new_metadata)
                new_encrypted_metadata = new_cipher.encrypt(new_metadata_json.encode('utf-8'))
                
                # 存储新的加密元数据
                new_base_uuid = os.path.splitext(new_encrypted_filename)[0]  # 获取新UUID部分
                new_metadata_filename = new_base_uuid + '.meta'
                new_metadata_path = os.path.join(os.path.dirname(encrypted_file_path), new_metadata_filename)
                
                with open(new_metadata_path, 'wb') as f:
                    f.write(new_encrypted_metadata)
                
                # 删除旧的加密文件和元数据文件
                os.remove(encrypted_file_path)
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
            
            # --- NEW: Delete old password and meta files AFTER saving new password and re-encrypting files ---
            # Delete the old encrypted password file and its corresponding meta file
            try:
                if os.path.exists(old_pwd_path):
                    os.remove(old_pwd_path)
                if os.path.exists(old_meta_path):
                    os.remove(old_meta_path)
            except Exception as e:
                print(f"删除旧密码文件时发生错误: {str(e)}")  # Use print instead of messagebox for internal errors
                # Log error but continue
            # --- END NEW ---

            messagebox.showinfo("成功", "密码修改成功，所有文件已重新加密！")
            
            # 刷新列表
            self.refresh_file_list()
            
            # 关闭窗口
            change_window.destroy()
            parent_window.destroy()
        except Exception as e:
            messagebox.showerror("错误", f"修改密码时发生错误: {str(e)}")

def main():
    # 检查是否已设置密码
    if is_password_set():
        # 如果已设置密码，显示验证界面
        root = tk.Tk() if not HAS_DND else tkinterdnd2.Tk()
        app = PasswordVerificationApp(root)
    else:
        # 如果未设置密码，显示设置界面
        root = tk.Tk() if not HAS_DND else tkinterdnd2.Tk()
        app = PasswordSetupApp(root)
    
    root.mainloop()

if __name__ == "__main__":
    main()