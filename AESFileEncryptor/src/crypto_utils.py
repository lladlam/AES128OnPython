"""
AES-128加密解密工具模块
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import uuid
import tempfile
import ctypes
from ctypes import wintypes
import shutil
import json
import time


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
    data_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'Data')
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


def decrypt_file(encrypted_file_path, password, output_dir=None, output_filename=None):
    """
    解密文件
    :param encrypted_file_path: 加密文件路径
    :param password: 密码
    :param output_dir: 解密文件输出目录（可选，默认为当前目录）
    :param output_filename: 解密文件输出名称（可选，如果指定则使用该名称）
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
    data_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'Data')
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