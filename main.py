"""
AES文件加密软件主程序（整合版）
"""
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
        self.root = root
        self.root.title("AES-128文件加密器")
        self.root.geometry("800x600")
        
        # 存储主密码
        self.master_password = master_password
        
        # 当前选中的加密文件
        self.selected_encrypted_file = None
        
        self.setup_ui()
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
        
        # 添加版权信息标签
        copyright_label = ttk.Label(main_frame, text="AES128OnPython 版权所有 (C) 2025 lladlam，许可证基于GPL-3.0-or-later", 
                                   font=("Arial", 8), foreground="gray")
        copyright_label.grid(row=5, column=0, columnspan=4, sticky=(tk.S+tk.E), padx=5, pady=5)
    
    def refresh_file_list(self):
        """
        刷新加密文件列表
        """
        # 清空当前列表
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        try:
            # 使用主密码获取加密文件列表
            encrypted_files = get_encrypted_files_list(self.master_password)
            
            # 添加到列表中
            for file_info in encrypted_files:
                # 格式化文件大小
                size_str = f"{file_info['size']} 字节"
                if file_info['size'] > 1024:
                    size_str = f"{file_info['size']/1024:.1f} KB"
                if file_info['size'] > 1024*1024:
                    size_str = f"{file_info['size']/(1024*1024):.1f} MB"
                
                # 格式化修改时间
                mod_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_info['mod_time']))
                
                # 添加到列表
                self.file_tree.insert("", "end", values=(
                    file_info['original_name'],
                    file_info['encrypted_name'],
                    size_str,
                    mod_time_str
                ), tags=(file_info['encrypted_path'],))  # 将完整路径存储在tags中
        except Exception as e:
            messagebox.showerror("错误", f"获取文件列表失败: {str(e)}")
    
    def on_file_select(self, event):
        """
        当在列表中选择文件时触发
        """
        selection = self.file_tree.selection()
        if selection:
            item = self.file_tree.item(selection[0])
            # 从tags中获取加密文件的完整路径
            if item['tags']:
                self.selected_encrypted_file = item['tags'][0]
    
    def add_file(self):
        """
        添加文件并加密
        """
        file_path = filedialog.askopenfilename(
            title="选择要加密的文件",
            filetypes=[
                ("所有文件", "*.*"),
                ("文本文件", "*.txt"),
                ("图片文件", "*.jpg *.jpeg *.png *.gif"),
                ("PDF文件", "*.pdf")
            ]
        )
        
        if not file_path:
            return
        
        # 使用主密码加密文件
        self.encrypt_file_with_master_password(file_path)
    
    def decrypt_selected_file(self):
        """
        解密选中的加密文件
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return
        
        try:
            # 获取加密文件的原始文件名
            import json
            
            # 获取当前文件的信息
            all_files = get_encrypted_files_list(self.master_password)
            current_file_info = None
            for file_info in all_files:
                if file_info['encrypted_path'] == self.selected_encrypted_file:
                    current_file_info = file_info
                    break
            
            # 获取原始文件名
            original_name = current_file_info['original_name'] if current_file_info else "decrypted_file"
            
            # 让用户选择保存位置和文件名
            save_path = filedialog.asksaveasfilename(
                title="选择解密文件保存位置",
                defaultextension=os.path.splitext(original_name)[1] or ".*",
                initialfile=original_name,
                filetypes=[
                    ("所有文件", "*.*"),
                    ("文本文件", "*.txt"),
                    ("图片文件", "*.jpg *.jpeg *.png *.gif"),
                    ("PDF文件", "*.pdf")
                ]
            )
            
            if not save_path:
                return  # 用户取消了操作

            # 使用主密码解密文件到用户选择的位置
            final_path = decrypt_file(
                self.selected_encrypted_file, 
                self.master_password,
                output_dir=os.path.dirname(save_path),
                output_filename=os.path.basename(save_path),
                delete_on_success=True
            )
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "解密成功！\n")
            self.result_text.insert(tk.END, f"加密文件: {os.path.basename(self.selected_encrypted_file)}\n")
            self.result_text.insert(tk.END, f"解密后文件: {final_path}\n")
            
            messagebox.showinfo("成功", f"文件已解密!\n解密文件路径: {final_path}")
            
            # 刷新文件列表
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("解密失败", f"发生错误: {str(e)}")
    
    def view_selected_file(self):
        """
        查看选中的加密文件内容（通过临时解密到系统Temp文件夹）
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return
        
        import tempfile
        import time
        
        try:
            # 获取加密文件的原始文件名用于生成混淆的临时文件名
            import json
            
            # 获取当前文件的信息
            all_files = get_encrypted_files_list(self.master_password)
            current_file_info = None
            for file_info in all_files:
                if file_info['encrypted_path'] == self.selected_encrypted_file:
                    current_file_info = file_info
                    break
            
            # 获取原始文件名
            original_name = current_file_info['original_name'] if current_file_info else "temp_file"
            
            # 生成混淆的临时文件名：当前时间 + 混淆的原文件名
            timestamp = str(int(time.time() * 1000))  # 毫秒级时间戳
            temp_filename = f"{timestamp}_{original_name}"
            
            # 使用主密码解密文件到系统Temp文件夹，使用混淆的文件名
            temp_file_path = decrypt_file(
                self.selected_encrypted_file, 
                self.master_password,
                output_dir=tempfile.gettempdir(),
                output_filename=temp_filename
            )
            
            # 尝试用系统默认程序打开临时文件
            os.startfile(temp_file_path)  # Windows系统
            
            # 启动后台线程或计时器来稍后删除临时文件
            # 这里简单地使用一个计时器，等待一段时间后自动删除文件
            self.root.after(10000, lambda: self._delete_temp_file(temp_file_path))  # 10秒后删除
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"文件已临时解密到: {temp_file_path}\n")
            self.result_text.insert(tk.END, "文件将在10秒后自动删除。\n")
            
        except Exception as e:
            messagebox.showerror("查看失败", f"发生错误: {str(e)}")
    
    def _delete_temp_file(self, file_path):
        """
        删除临时文件
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                self.result_text.insert(tk.END, f"\n临时文件已删除: {file_path}")
        except Exception as e:
            # 如果删除失败，通常是因为用户已经手动删除了文件或权限问题
            pass
    
    def encrypt_file_with_master_password(self, file_path):
        """
        使用主密码加密文件
        """
        if not file_path:
            messagebox.showerror("错误", "请选择要加密的文件")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("错误", "所选文件不存在")
            return
        
        try:
            # 执行加密（使用主密码）
            encrypted_file_path = encrypt_file(file_path, self.master_password)
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "加密成功！\n")
            self.result_text.insert(tk.END, f"原文件: {file_path}\n")
            self.result_text.insert(tk.END, f"加密后文件: {os.path.basename(encrypted_file_path)}\n")
            self.result_text.insert(tk.END, f"\n注意: 加密后的文件已存储到Data文件夹中，并使用了混淆文件名\n")
            
            messagebox.showinfo("成功", f"文件已加密!\n加密文件名: {os.path.basename(encrypted_file_path)}")
            
            # 刷新文件列表
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("加密失败", f"发生错误: {str(e)}")


def main():
    """
    主程序入口
    """
    # 确保Data目录存在
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 检查Data目录中的文件
    has_meta_files = False
    has_pwd_files = False
    
    if os.path.exists(DATA_DIR):
        files = os.listdir(DATA_DIR)
        has_meta_files = any(f.endswith('.meta') for f in files)
        has_pwd_files = any(f.endswith('.pwd') for f in files)
    
    # 如果没有meta文件，表示没有设置过密码
    if not has_meta_files:
        # 没有设置过密码，清空Data文件夹（以防有残留文件）并显示设置界面
        clear_data_folder()
        root = tk.Tk()
        app = PasswordSetupApp(root)
        root.mainloop()
    elif has_meta_files and not has_pwd_files:
        # 有meta文件但没有pwd文件，表示密码文件被删除，需要重置
        clear_data_folder()
        root = tk.Tk()
        app = PasswordSetupApp(root)
        root.mainloop()
    else:
        # 既有meta文件也有pwd文件，显示验证界面
        root = tk.Tk()
        app = PasswordVerificationApp(root)
        root.mainloop()


if __name__ == "__main__":
    main()