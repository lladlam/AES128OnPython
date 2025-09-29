import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
import json
import tempfile
from Crypto.Cipher import AES, ChaCha20_Poly1305
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

class StreamCipher:
    """
    流式加密解密类，适用于大文件
    使用ChaCha20-Poly1305算法，支持分块加密解密
    """
    
    def __init__(self, password):
        """
        初始化，根据密码生成密钥
        :param password: 用户提供的密码
        """
        # 使用SHA-256哈希函数将密码转换为32字节密钥
        self.key = hashlib.sha256(password.encode()).digest()
    
    def encrypt_stream(self, input_path, output_path, chunk_size=64*1024):
        """
        流式加密大文件
        :param input_path: 输入文件路径
        :param output_path: 输出文件路径
        :param chunk_size: 块大小
        """
        # 生成随机nonce
        nonce = get_random_bytes(12)  # ChaCha20-Poly1305需要12字节nonce
        
        # 创建加密器
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        
        # 原子写入加密文件
        temp_output_path = output_path + '.tmp'
        
        with open(input_path, 'rb') as infile, open(temp_output_path, 'wb') as outfile:
            # 先写入nonce
            outfile.write(nonce)
            
            # 分块处理文件
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                if len(chunk) % 16 != 0:  # 如果不是16的倍数，需要特殊处理
                    # ChaCha20-Poly1305不需要填充
                    pass
                encrypted_chunk = cipher.encrypt(chunk)
                outfile.write(encrypted_chunk)
            
            # 写入认证标签
            tag = cipher.digest()
            outfile.write(tag)
        
        # 原子重命名
        os.replace(temp_output_path, output_path)
    
    def decrypt_stream(self, input_path, output_path, chunk_size=64*1024):
        """
        流式解密大文件
        :param input_path: 输入文件路径
        :param output_path: 输出文件路径
        :param chunk_size: 块大小
        """
        with open(input_path, 'rb') as infile:
            # 读取nonce（前12字节）
            nonce = infile.read(12)
            
            # 移动到文件末尾前16字节处读取认证标签
            infile.seek(-16, os.SEEK_END)
            tag = infile.read(16)
            
            # 重新定位到数据开始位置
            infile.seek(12, os.SEEK_SET)
            remaining_size = infile.tell() - (os.path.getsize(input_path) - 16)
            data_size = os.path.getsize(input_path) - 12 - 16  # 排除nonce和tag
            
            # 创建解密器
            cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
            
            # 原子写入解密文件
            temp_output_path = output_path + '.tmp'
            
            with open(temp_output_path, 'wb') as outfile:
                # 分块处理加密数据
                bytes_read = 0
                while bytes_read < data_size:
                    # 计算当前块大小
                    current_chunk_size = min(chunk_size, data_size - bytes_read)
                    chunk = infile.read(current_chunk_size)
                    
                    if len(chunk) == 0:
                        break
                        
                    bytes_read += len(chunk)
                    
                    # 解密当前块
                    decrypted_chunk = cipher.decrypt(chunk)
                    outfile.write(decrypted_chunk)
                
                # 验证认证标签
                try:
                    cipher.verify(tag)
                except ValueError as e:
                    raise ValueError("密码错误或文件损坏") from e
        
        # 原子重命名
        os.replace(temp_output_path, output_path)
    
    def encrypt(self, plaintext):
        """
        加密数据（传统方法，用于小数据如元数据）
        :param plaintext: 待加密的数据
        :return: 加密后的数据 (bytes)
        """
        # 生成随机nonce
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        tag = cipher.digest()
        
        # 将nonce、密文和认证标签一起返回
        return nonce + ciphertext + tag
    
    def decrypt(self, ciphertext):
        """
        解密数据（传统方法，用于小数据如元数据）
        :param ciphertext: 待解密的数据，包含nonce、密文和认证标签
        :return: 解密后的数据 (bytes)
        """
        # 提取nonce（前12字节）
        nonce = ciphertext[:12]
        # 提取认证标签（后16字节）
        tag = ciphertext[-16:]
        # 提取加密数据
        encrypted_data = ciphertext[12:-16]
        
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 验证认证标签
        try:
            cipher.verify(tag)
        except ValueError as e:
            # 如果解密失败，可能是密码错误
            raise ValueError("密码错误或文件损坏") from e
            
        return decrypted_data

def reencrypt_file_chunked(encrypted_input_path, decrypted_password, new_encrypted_output_path, new_password, metadata_path, new_metadata_path, chunk_size=8192):
    """
    重新加密文件（解密旧文件并使用新密码加密）
    注意：由于AES加密中IV随机性，我们无法真正分块解密再加密，
    因此这里仍然需要一次性解密整个文件再加密
    :param encrypted_input_path: 旧加密文件路径
    :param decrypted_password: 旧密码
    :param new_encrypted_output_path: 新加密文件路径
    :param new_password: 新密码
    :param metadata_path: 旧元数据路径
    :param new_metadata_path: 新元数据路径
    :param chunk_size: 分块大小（仅在将来扩展时使用）
    """
    # 读取并解密旧文件
    with open(encrypted_input_path, 'rb') as f:
        encrypted_data = f.read()
    
    old_cipher = AESCipher(decrypted_password)
    decrypted_data = old_cipher.decrypt(encrypted_data)
    
    # 获取元数据
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
    
    # 原子写入新的加密文件
    temp_new_encrypted_path = new_encrypted_output_path + '.tmp'
    with open(temp_new_encrypted_path, 'wb') as f:
        f.write(new_encrypted_data)
    # 原子重命名
    os.replace(temp_new_encrypted_path, new_encrypted_output_path)
    
    # 创建新的加密元数据
    new_metadata = {
        "original_filename": original_filename,
        "original_filepath": original_filepath,
        "encrypted_filename": os.path.basename(new_encrypted_output_path),
        "creation_time": creation_time
    }
    
    # 序列化新元数据并加密
    new_metadata_json = json.dumps(new_metadata)
    new_encrypted_metadata = new_cipher.encrypt(new_metadata_json.encode('utf-8'))
    
    # 原子写入新的加密元数据
    temp_new_metadata_path = new_metadata_path + '.tmp'
    with open(temp_new_metadata_path, 'wb') as f:
        f.write(new_encrypted_metadata)
    # 原子重命名
    os.replace(temp_new_metadata_path, new_metadata_path)

def encrypt_file(file_path, password, encryption_method=None):
    """
    加密文件
    :param file_path: 文件路径
    :param password: 密码
    :param encryption_method: 加密方法，如果为None则从配置中读取
    :return: 加密后文件路径
    """
    # 获取加密方式
    if encryption_method is None:
        config = load_config()
        encryption_method = config.get("encryption_method", "AES")
    
    # 创建Data目录（如果不存在）
    data_dir = os.path.join(os.path.dirname(__file__), 'Data')
    data_dir = os.path.abspath(data_dir)
    os.makedirs(data_dir, exist_ok=True)
    
    # 获取原文件名（不含路径）
    original_filename = os.path.basename(file_path)
    
    # 生成混淆的文件名
    encrypted_filename = str(uuid.uuid4()) + '.llaes'  # 使用.llaes扩展名
    encrypted_file_path = os.path.join(data_dir, encrypted_filename)
    
    # 创建加密器
    cipher = get_cipher(password, encryption_method)
    
    if encryption_method == "STREAM":
        # 使用流式加密处理大文件
        temp_encrypted_file_path = encrypted_file_path + '.tmp'
        cipher.encrypt_stream(file_path, temp_encrypted_file_path)
        # 原子重命名
        os.replace(temp_encrypted_file_path, encrypted_file_path)
        
        # 单独加密文件内容，但保存元数据到单独的文件
        # 首先我们需要临时解密文件以获取内容，但这会导致重复处理
        # 更好的方式是直接保存元数据
        metadata_content = {
            "original_filename": original_filename,
            "original_filepath": file_path,  # 保留原始路径信息
            "encrypted_filename": encrypted_filename,
            "creation_time": time.time(),
            "encryption_method": encryption_method  # 记录加密方式
        }
        
        # 序列化元数据并加密
        metadata_json = json.dumps(metadata_content)
        encrypted_metadata = cipher.encrypt(metadata_json.encode('utf-8'))
    else:  # 使用AES
        # 读取原始文件内容
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # 加密数据
        encrypted_data = cipher.encrypt(file_data)
        
        # 原子写入加密文件
        temp_encrypted_file_path = encrypted_file_path + '.tmp'
        with open(temp_encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        # 原子重命名
        os.replace(temp_encrypted_file_path, encrypted_file_path)
        
        # 创建加密的元数据
        metadata_content = {
            "original_filename": original_filename,
            "original_filepath": file_path,  # 保留原始路径信息
            "encrypted_filename": encrypted_filename,
            "creation_time": time.time(),
            "encryption_method": encryption_method  # 记录加密方式
        }
        
        # 序列化元数据并加密
        metadata_json = json.dumps(metadata_content)
        encrypted_metadata = cipher.encrypt(metadata_json.encode('utf-8'))
    
    # 存储加密的元数据（使用与加密文件相同的UUID但不同扩展名）
    base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
    metadata_filename = base_uuid + '.meta'  # 使用.meta扩展名
    metadata_path = os.path.join(data_dir, metadata_filename)
    
    # 原子写入元数据文件
    temp_metadata_path = metadata_path + '.tmp'
    with open(temp_metadata_path, 'wb') as f:
        f.write(encrypted_metadata)
    # 原子重命名
    os.replace(temp_metadata_path, metadata_path)
    
    return encrypted_file_path

def reencrypt_file_chunked(encrypted_input_path, decrypted_password, new_encrypted_output_path, new_password, metadata_path, new_metadata_path, chunk_size=8192):
    """
    使用分块方式重新加密文件（解密旧文件并使用新密码加密）
    :param encrypted_input_path: 旧加密文件路径
    :param decrypted_password: 旧密码
    :param new_encrypted_output_path: 新加密文件路径
    :param new_password: 新密码
    :param metadata_path: 旧元数据路径
    :param new_metadata_path: 新元数据路径
    :param chunk_size: 分块大小
    """
    # 读取并解密旧文件
    with open(encrypted_input_path, 'rb') as f:
        encrypted_data = f.read()
    
    old_cipher = AESCipher(decrypted_password)
    decrypted_data = old_cipher.decrypt(encrypted_data)
    
    # 获取元数据
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
    
    # 原子写入新的加密文件
    temp_new_encrypted_path = new_encrypted_output_path + '.tmp'
    with open(temp_new_encrypted_path, 'wb') as f:
        f.write(new_encrypted_data)
    # 原子重命名
    os.replace(temp_new_encrypted_path, new_encrypted_output_path)
    
    # 创建新的加密元数据
    new_metadata = {
        "original_filename": original_filename,
        "original_filepath": original_filepath,
        "encrypted_filename": os.path.basename(new_encrypted_output_path),
        "creation_time": creation_time
    }
    
    # 序列化新元数据并加密
    new_metadata_json = json.dumps(new_metadata)
    new_encrypted_metadata = new_cipher.encrypt(new_metadata_json.encode('utf-8'))
    
    # 原子写入新的加密元数据
    temp_new_metadata_path = new_metadata_path + '.tmp'
    with open(temp_new_metadata_path, 'wb') as f:
        f.write(new_encrypted_metadata)
    # 原子重命名
    os.replace(temp_new_metadata_path, new_metadata_path)

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
    # 获取加密的元数据文件路径
    encrypted_filename = os.path.basename(encrypted_file_path)
    base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
    metadata_filename = base_uuid + '.meta'
    metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
    
    # 从元数据中获取加密方式
    encryption_method = "AES"  # 默认值
    original_filename = None
    
    if os.path.exists(metadata_path):
        # 尝试使用AES解密元数据（向后兼容）
        try:
            # 读取加密的元数据
            with open(metadata_path, 'rb') as f:
                encrypted_metadata = f.read()
            
            # 尝试AES解密
            aes_cipher = AESCipher(password)
            decrypted_metadata_bytes = aes_cipher.decrypt(encrypted_metadata)
            decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
            metadata = json.loads(decrypted_metadata_json)
            
            original_filename = metadata.get("original_filename", None)
            encryption_method = metadata.get("encryption_method", "AES")
        except:
            # 如果AES解密失败，尝试流式解密
            try:
                stream_cipher = StreamCipher(password)
                decrypted_metadata_bytes = stream_cipher.decrypt(encrypted_metadata)
                decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                metadata = json.loads(decrypted_metadata_json)
                
                original_filename = metadata.get("original_filename", None)
                encryption_method = metadata.get("encryption_method", "STREAM")
            except:
                # 如果两种方式都失败，则认为密码错误或文件损坏
                raise ValueError("密码错误或元数据文件损坏")
    
    # 创建相应类型的解密器
    cipher = get_cipher(password, encryption_method)
    
    # 根据加密方式解密文件
    if encryption_method == "STREAM":
        # 使用临时文件进行流式解密
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as temp_output:
            temp_output_path = temp_output.name
        
        try:
            # 执行流式解密
            cipher.decrypt_stream(encrypted_file_path, temp_output_path)
            # 读取解密后的内容
            with open(temp_output_path, 'rb') as f:
                decrypted_data = f.read()
        finally:
            # 删除临时解密文件
            if os.path.exists(temp_output_path):
                os.remove(temp_output_path)
    else:  # AES
        # 读取加密文件内容
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 解密数据
        decrypted_data = cipher.decrypt(encrypted_data)
    
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
    
    # 原子写入解密文件
    temp_decrypted_file_path = decrypted_file_path + '.tmp'
    with open(temp_decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    # 原子重命名
    os.replace(temp_decrypted_file_path, decrypted_file_path)
    
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
    
    for filename in os.listdir(data_dir):
        if filename.endswith('.llaes'):
            encrypted_file_path = os.path.join(data_dir, filename)
            
            # 获取对应元数据文件
            base_uuid = os.path.splitext(filename)[0]  # 获取UUID部分
            metadata_filename = base_uuid + '.meta'
            metadata_path = os.path.join(data_dir, metadata_filename)
            
            original_filename = "未知文件"
            encryption_method = "AES"  # 默认值
            
            if os.path.exists(metadata_path):
                # 尝试使用AES解密元数据（向后兼容）
                try:
                    # 读取加密的元数据
                    with open(metadata_path, 'rb') as f:
                        encrypted_metadata = f.read()
                    
                    # 尝试AES解密
                    aes_cipher = AESCipher(password)
                    decrypted_metadata_bytes = aes_cipher.decrypt(encrypted_metadata)
                    decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                    metadata = json.loads(decrypted_metadata_json)
                    
                    original_filename = metadata.get("original_filename", "未知文件")
                    encryption_method = metadata.get("encryption_method", "AES")
                except:
                    # 如果AES解密失败，尝试流式解密
                    try:
                        stream_cipher = StreamCipher(password)
                        decrypted_metadata_bytes = stream_cipher.decrypt(encrypted_metadata)
                        decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                        metadata = json.loads(decrypted_metadata_json)
                        
                        original_filename = metadata.get("original_filename", "未知文件")
                        encryption_method = metadata.get("encryption_method", "STREAM")
                    except:
                        # 如果两种方式都失败，则标记为解密失败
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
                "mod_time": mod_time,
                "encryption_method": encryption_method  # 添加加密方式信息
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
        # 获取加密的元数据文件路径以确定加密方式
        encrypted_filename = os.path.basename(encrypted_file_path)
        base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
        metadata_filename = base_uuid + '.meta'
        metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
        
        # 从元数据中获取加密方式
        encryption_method = "AES"  # 默认值
        
        if os.path.exists(metadata_path):
            # 尝试使用AES解密元数据（向后兼容）
            try:
                # 读取加密的元数据
                with open(metadata_path, 'rb') as f:
                    encrypted_metadata = f.read()
                
                # 尝试AES解密
                aes_cipher = AESCipher(password)
                decrypted_metadata_bytes = aes_cipher.decrypt(encrypted_metadata)
                decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                metadata = json.loads(decrypted_metadata_json)
                
                encryption_method = metadata.get("encryption_method", "AES")
            except:
                # 如果AES解密失败，尝试流式解密
                try:
                    stream_cipher = StreamCipher(password)
                    decrypted_metadata_bytes = stream_cipher.decrypt(encrypted_metadata)
                    decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                    metadata = json.loads(decrypted_metadata_json)
                    
                    encryption_method = metadata.get("encryption_method", "STREAM")
                except:
                    # 如果两种方式都失败，则认为密码错误或文件损坏
                    return "密码错误或元数据文件损坏"
        
        # 创建相应类型的解密器
        cipher = get_cipher(password, encryption_method)
        
        # 根据加密方式解密文件
        if encryption_method == "STREAM":
            # 使用临时文件进行流式解密
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as temp_output:
                temp_output_path = temp_output.name
            
            try:
                # 执行流式解密
                cipher.decrypt_stream(encrypted_file_path, temp_output_path)
                # 读取解密后的内容
                with open(temp_output_path, 'rb') as f:
                    decrypted_data = f.read()
            finally:
                # 删除临时解密文件
                if os.path.exists(temp_output_path):
                    os.remove(temp_output_path)
        else:  # AES
            # 读取加密文件内容
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
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
        "copy_encrypted_file": False,  # 默认复制解密后的文件
        "encryption_method": "AES"  # 默认使用AES加密
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

def get_cipher(password, encryption_method=None):
    """
    根据配置获取相应的加密器
    :param password: 密码
    :param encryption_method: 加密方法，如果为None则从配置中读取
    :return: 加密器实例
    """
    if encryption_method is None:
        config = load_config()
        encryption_method = config.get("encryption_method", "AES")
    
    if encryption_method == "STREAM":
        return StreamCipher(password)
    else:  # 默认使用AES
        return AESCipher(password)

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
    
    # 原子写入密码文件
    temp_pwd_path = ENCRYPTED_PASSWORD_FILE + '.tmp'
    with open(temp_pwd_path, 'wb') as f:
        f.write(encrypted_data)
    # 原子重命名
    os.replace(temp_pwd_path, ENCRYPTED_PASSWORD_FILE)
    
    # 创建一个元数据文件，记录密码文件的真实名称（也加密存储）
    metadata = {"filename": encrypted_filename}
    metadata_json = json.dumps(metadata)
    encrypted_metadata = _encrypt_data(metadata_json, password)
    
    metadata_filename = str(uuid.uuid4()) + '.meta'
    metadata_path = os.path.join(DATA_DIR, metadata_filename)
    
    # 原子写入元数据文件
    temp_meta_path = metadata_path + '.tmp'
    with open(temp_meta_path, 'wb') as f:
        f.write(encrypted_metadata)
    # 原子重命名
    os.replace(temp_meta_path, metadata_path)

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
        
        # 添加版本号标签 (V2.4-beta2)
        self.version_label = ttk.Label(bottom_frame, text="V2.4-beta2", 
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
            # 获取原始文件名（从元数据中）
            encrypted_filename = os.path.basename(encrypted_file_path)
            base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
            metadata_filename = base_uuid + '.meta'
            metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
            
            original_filename = "decrypted_file"
            encryption_method = "AES"  # 默认值
            
            if os.path.exists(metadata_path):
                # 尝试使用AES解密元数据（向后兼容）
                try:
                    # 读取加密的元数据
                    with open(metadata_path, 'rb') as f:
                        encrypted_metadata = f.read()
                    
                    # 尝试AES解密
                    aes_cipher = AESCipher(self.master_password)
                    decrypted_metadata_bytes = aes_cipher.decrypt(encrypted_metadata)
                    decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                    metadata = json.loads(decrypted_metadata_json)
                    
                    original_filename = metadata.get("original_filename", "decrypted_file")
                    encryption_method = metadata.get("encryption_method", "AES")
                except:
                    # 如果AES解密失败，尝试流式解密
                    try:
                        stream_cipher = StreamCipher(self.master_password)
                        decrypted_metadata_bytes = stream_cipher.decrypt(encrypted_metadata)
                        decrypted_metadata_json = decrypted_metadata_bytes.decode('utf-8')
                        metadata = json.loads(decrypted_metadata_json)
                        
                        original_filename = metadata.get("original_filename", "decrypted_file")
                        encryption_method = metadata.get("encryption_method", "STREAM")
                    except:
                        # 如果两种方式都失败，使用默认值
                        original_filename = "decrypted_file"
            
            # 创建相应类型的解密器
            cipher = get_cipher(self.master_password, encryption_method)
            
            # 根据加密方式解密文件
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as temp_output:
                temp_output_path = temp_output.name
            
            try:
                if encryption_method == "STREAM":
                    # 执行流式解密
                    cipher.decrypt_stream(encrypted_file_path, temp_output_path)
                else:  # AES
                    # 读取加密文件内容
                    with open(encrypted_file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # 解密数据
                    decrypted_data = cipher.decrypt(encrypted_data)
                    
                    # 原子写入解密文件到临时位置
                    temp_file_path = temp_output_path + '.tmp'
                    with open(temp_file_path, 'wb') as f:
                        f.write(decrypted_data)
                    # 原子重命名
                    os.replace(temp_file_path, temp_output_path)
                
                # 检查目标临时文件是否存在且包含数据
                if not os.path.exists(temp_output_path):
                    raise Exception("解密失败：未生成临时文件")
                
                # 调用外部命令将文件路径写入剪贴板（在Windows上）
                import subprocess
                
                # 创建一个包含文件路径的临时文件
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    f.write(temp_output_path)
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
                    $fileDropList.Add('{temp_output_path.replace(os.sep, "/")}')
                    [System.Windows.Forms.Clipboard]::SetFileDropList($fileDropList)
                    '''
                    subprocess.run(['powershell', '-Command', ps_script], check=True, capture_output=True)
                    
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, f"已将解密文件复制到剪贴板: {original_filename}\n")
                    messagebox.showinfo("成功", f"已将解密文件复制到剪贴板: {original_filename}")
                except subprocess.CalledProcessError:
                    # 如果PowerShell方法失败，使用另一种方法
                    # 使用系统命令行将路径复制到剪贴板
                    os.system(f'echo {temp_output_path} | clip')
                    
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, f"已将解密文件路径复制到剪贴板: {original_filename}\n（使用备选方法）")
                    messagebox.showinfo("成功", f"已将解密文件路径复制到剪贴板: {original_filename}")
                finally:
                    # 清理临时文件
                    try:
                        os.unlink(temp_list_file)
                        os.unlink(temp_output_path)  # 也要清理临时解密文件
                    except:
                        pass
            except Exception as e:
                # 确保临时文件被清理
                try:
                    if os.path.exists(temp_output_path):
                        os.remove(temp_output_path)
                except:
                    pass
                raise e
            
        except Exception as e:
            messagebox.showerror("复制失败", f"复制解密文件时发生错误: {str(e)}")

    def add_file(self):
        """
        添加文件进行加密
        """
        file_paths = filedialog.askopenfilenames(title="选择要加密的文件")
        
        if not file_paths:
            return
        
        # 获取当前配置的加密方式
        encryption_method = self.config.get("encryption_method", "AES")
        
        success_count = 0
        for file_path in file_paths:
            try:
                encrypted_path = encrypt_file(file_path, self.master_password, encryption_method)
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
        import tempfile
        import time
        import uuid
        
        # 生成临时文件名以避免冲突
        timestamp = str(int(time.time() * 1000))  # 毫秒级时间戳
        original_filename = os.path.basename(self.selected_encrypted_file)
        # 获取原文件扩展名
        _, ext = os.path.splitext(original_filename)
        temp_filename = f"temp_{timestamp}_{os.path.basename(original_filename)}_{uuid.uuid4().hex[:8]}{ext}"
        
        # 使用临时目录存储临时文件
        temp_file_path = os.path.join(tempfile.gettempdir(), temp_filename)
        
        # 临时文件管理：使用 try/finally 确保文件会被删除
        temp_file_created = False
        try:
            # 使用当前主密码解密文件到临时位置
            with open(self.selected_encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            cipher = AESCipher(self.master_password)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # 原子写入临时文件
            temp_path_with_suffix = temp_file_path + '.tmp'
            with open(temp_path_with_suffix, 'wb') as f:
                f.write(decrypted_data)
            
            # 原子重命名
            os.replace(temp_path_with_suffix, temp_file_path)
            temp_file_created = True
            
            # 在系统默认程序中打开临时文件
            os.startfile(temp_file_path)  # Windows系统
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"文件已临时解密到: {temp_file_path}\n")
            self.result_text.insert(tk.END, "文件将在后台自动删除。\n")
            
        except Exception as e:
            messagebox.showerror("查看失败", f"发生错误: {str(e)}")
            # 如果创建了临时文件但在打开时出错，确保删除临时文件
            if temp_file_created and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except:
                    pass  # 即使删除失败也不影响错误提示
        finally:
            # 启动后台线程在一段时间后删除临时文件
            # 这里使用 after 方法在GUI线程中安排删除任务
            self.root.after(10000, lambda: self._safely_delete_file(temp_file_path))  # 10秒后删除

    def _safely_delete_file(self, file_path):
        """
        安全删除文件的辅助方法
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                self.result_text.insert(tk.END, f"\n临时文件已删除: {file_path}")
        except Exception as e:
            # 记录删除失败，但不显示给用户
            print(f"删除临时文件失败 {file_path}: {str(e)}")

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
        settings_window.geometry("400x400")
        
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
        
        # 加密方式选择
        encryption_var = tk.StringVar(value=self.config.get("encryption_method", "AES"))
        ttk.Label(main_frame, text="加密方式:").grid(row=3, column=0, sticky=tk.W, pady=5)
        encryption_combo = ttk.Combobox(main_frame, textvariable=encryption_var, 
                                       values=["AES", "STREAM"], state="readonly")
        encryption_combo.grid(row=3, column=1, pady=5, sticky=(tk.W, tk.E))
        
        # 重新加密所有文件按钮
        reencrypt_btn = ttk.Button(main_frame, text="更改加密方式并重新加密所有文件", 
                                  command=lambda: self.reencrypt_all_files(encryption_var.get(), settings_window))
        reencrypt_btn.grid(row=4, column=0, columnspan=2, pady=10)
        
        # 修改密码按钮
        change_password_btn = ttk.Button(main_frame, text="修改密码", command=lambda: self.open_change_password(settings_window))
        change_password_btn.grid(row=5, column=0, columnspan=2, pady=10)
        
        # 配置列权重
        main_frame.columnconfigure(1, weight=1)
        
        # 保存设置\n        def save_settings():\n            # 检查加密方式是否已更改\n            old_encryption_method = self.config.get(\"encryption_method\", \"AES\")\n            new_encryption_method = encryption_var.get()\n            \n            # 更新配置\n            self.config[\"encryption_method\"] = new_encryption_method\n            save_config(self.config)\n            \n            if old_encryption_method != new_encryption_method:\n                # 如果加密方式已更改，提示用户需要重新加密文件\n                if messagebox.askyesno(\"加密方式已更改\", f\"加密方式已从{old_encryption_method}更改为{new_encryption_method}。\\n需要重新加密所有文件以使用新的加密方式。\\n是否现在重新加密所有文件？\"):\n                    # 在新线程中执行重新加密，避免阻塞UI\n                    import threading\n                    reencrypt_thread = threading.Thread(target=self._reencrypt_all_files_background, \n                                                        args=(new_encryption_method, parent_window))\n                    reencrypt_thread.start()\n                    \n                    messagebox.showinfo(\"设置已保存\", f\"设置已保存！加密方式已更新为{new_encryption_method}。\\n正在后台重新加密所有文件...\")\n                else:\n                    messagebox.showinfo(\"设置已保存\", f\"设置已保存！请注意：加密方式已更新为{new_encryption_method}，\\n但现有文件仍使用{old_encryption_method}加密，\\n您可以在以后重新加密它们。\")\n            else:\n                messagebox.showinfo(\"成功\", \"设置已保存！加密方式未更改。\")\n        \n        # 保存按钮\n        save_btn = ttk.Button(main_frame, text=\"仅保存设置\", command=save_settings)\n        save_btn.grid(row=6, column=0, columnspan=2, pady=10)

    def reencrypt_all_files(self, new_encryption_method, parent_window):
        """
        更改加密方式并重新加密所有文件
        """
        if not messagebox.askyesno("确认", f"确定要更改为{new_encryption_method}加密并重新加密所有文件吗？\n此操作可能需要较长时间。"):
            return
        
        try:
            # 获取所有加密文件的列表
            encrypted_files = get_encrypted_files_list(self.master_password)
            
            # 更新配置
            self.config["encryption_method"] = new_encryption_method
            save_config(self.config)
            
            # 创建进度窗口
            progress_window = tk.Toplevel(parent_window)
            progress_window.title("重新加密进度")
            progress_window.geometry("400x100")
            
            main_frame = ttk.Frame(progress_window, padding="20")
            main_frame.pack(fill='both', expand=True)
            
            ttk.Label(main_frame, text=f"正在使用{new_encryption_method}重新加密文件...").pack(pady=10)
            
            # 进度条
            progress = ttk.Progressbar(main_frame, length=300, mode='determinate')
            progress.pack(pady=10)
            
            # 配置进度条
            total_files = len(encrypted_files)
            if total_files > 0:
                progress['maximum'] = total_files
                progress['value'] = 0
                parent_window.update()
            
            # 重新加密所有文件
            for idx, file_info in enumerate(encrypted_files):
                encrypted_file_path = file_info['encrypted_path']
                
                # 获取对应的元数据文件路径
                encrypted_filename = os.path.basename(encrypted_file_path)
                base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
                metadata_filename = base_uuid + '.meta'
                metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
                
                # 生成新的混淆的文件名
                new_encrypted_filename = str(uuid.uuid4()) + '.llaes'
                new_encrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), new_encrypted_filename)
                
                # 生成新元数据文件路径
                new_base_uuid = os.path.splitext(new_encrypted_filename)[0]  # 获取新UUID部分
                new_metadata_filename = new_base_uuid + '.meta'
                new_metadata_path = os.path.join(os.path.dirname(encrypted_file_path), new_metadata_filename)
                
                # 使用新加密方式重新加密文件
                # 由于现在我们有不同类型的加密器，需要特殊处理
                with open(encrypted_file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # 根据原文件的加密方式创建对应的解密器
                old_encryption_method = file_info.get('encryption_method', 'AES')
                if old_encryption_method == 'STREAM':
                    old_cipher = StreamCipher(self.master_password)
                else:
                    old_cipher = AESCipher(self.master_password)
                
                try:
                    # 解密原文件
                    if old_encryption_method == 'STREAM':
                        # 对于流加密，我们需要流式解密到临时文件，然后重新加密
                        import tempfile
                        with tempfile.NamedTemporaryFile(delete=False) as temp_output:
                            temp_output_path = temp_output.name
                        
                        try:
                            old_cipher.decrypt_stream(encrypted_file_path, temp_output_path)
                            
                            # 读取解密后的内容
                            with open(temp_output_path, 'rb') as f:
                                decrypted_data = f.read()
                        finally:
                            # 删除临时解密文件
                            if os.path.exists(temp_output_path):
                                os.remove(temp_output_path)
                    else:  # AES
                        decrypted_data = old_cipher.decrypt(encrypted_data)
                    
                    # 获取元数据
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
                    
                    # 使用新加密方式加密文件内容
                    if new_encryption_method == 'STREAM':
                        new_cipher = StreamCipher(self.master_password)
                        # 使用流式加密到新文件
                        import tempfile
                        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
                            temp_input_path = temp_input.name
                        
                        try:
                            # 将解密数据写入临时文件
                            with open(temp_input_path, 'wb') as f:
                                f.write(decrypted_data)
                            
                            # 流式加密临时文件到目标文件
                            new_cipher.encrypt_stream(temp_input_path, new_encrypted_file_path)
                        finally:
                            # 删除临时输入文件
                            if os.path.exists(temp_input_path):
                                os.remove(temp_input_path)
                    else:  # AES
                        new_cipher = AESCipher(self.master_password)
                        new_encrypted_data = new_cipher.encrypt(decrypted_data)
                        
                        # 原子写入新的加密文件
                        temp_new_encrypted_path = new_encrypted_file_path + '.tmp'
                        with open(temp_new_encrypted_path, 'wb') as f:
                            f.write(new_encrypted_data)
                        # 原子重命名
                        os.replace(temp_new_encrypted_path, new_encrypted_file_path)
                    
                    # 创建新的加密元数据
                    new_metadata = {
                        "original_filename": original_filename,
                        "original_filepath": original_filepath,
                        "encrypted_filename": new_encrypted_filename,
                        "creation_time": creation_time,
                        "encryption_method": new_encryption_method  # 记录新的加密方式
                    }
                    
                    # 序列化新元数据并加密
                    new_metadata_json = json.dumps(new_metadata)
                    new_encrypted_metadata = new_cipher.encrypt(new_metadata_json.encode('utf-8'))
                    
                    # 原子写入新的加密元数据
                    temp_new_metadata_path = new_metadata_path + '.tmp'
                    with open(temp_new_metadata_path, 'wb') as f:
                        f.write(new_encrypted_metadata)
                    # 原子重命名
                    os.replace(temp_new_metadata_path, new_metadata_path)
                    
                    # 删除旧的加密文件和元数据文件
                    os.remove(encrypted_file_path)
                    if os.path.exists(metadata_path):
                        os.remove(metadata_path)
                except Exception as e:
                    print(f"重新加密文件失败 {encrypted_file_path}: {str(e)}")
                    # 继续处理下一个文件
                
                # 更新进度条
                progress['value'] = idx + 1
                progress_window.update()  # 更新窗口以刷新进度条
            
            messagebox.showinfo("完成", f"所有文件已重新加密为{new_encryption_method}格式！")
            
            # 刷新文件列表
            self.refresh_file_list()
            
            # 关闭进度窗口
            progress_window.destroy()
            
        except Exception as e:
            messagebox.showerror("错误", f"重新加密过程中发生错误: {str(e)}")

    def _reencrypt_all_files_background(self, new_encryption_method, parent_window):
        """
        在后台线程中重新加密所有文件
        """
        try:
            # 获取所有加密文件的列表
            encrypted_files = get_encrypted_files_list(self.master_password)
            
            # 创建进度窗口
            progress_window = tk.Toplevel(parent_window)
            progress_window.title("重新加密进度")
            progress_window.geometry("400x100")
            
            main_frame = ttk.Frame(progress_window, padding="20")
            main_frame.pack(fill='both', expand=True)
            
            ttk.Label(main_frame, text=f"正在使用{new_encryption_method}重新加密文件...").pack(pady=10)
            
            # 进度条
            progress = ttk.Progressbar(main_frame, length=300, mode='determinate')
            progress.pack(pady=10)
            
            # 配置进度条
            total_files = len(encrypted_files)
            if total_files > 0:
                progress['maximum'] = total_files
                progress['value'] = 0
                parent_window.update()
            
            # 重新加密所有文件
            for idx, file_info in enumerate(encrypted_files):
                encrypted_file_path = file_info['encrypted_path']
                
                # 获取对应的元数据文件路径
                encrypted_filename = os.path.basename(encrypted_file_path)
                base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
                metadata_filename = base_uuid + '.meta'
                metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
                
                # 生成新的混淆的文件名
                new_encrypted_filename = str(uuid.uuid4()) + '.llaes'
                new_encrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), new_encrypted_filename)
                
                # 生成新元数据文件路径
                new_base_uuid = os.path.splitext(new_encrypted_filename)[0]  # 获取新UUID部分
                new_metadata_filename = new_base_uuid + '.meta'
                new_metadata_path = os.path.join(os.path.dirname(encrypted_file_path), new_metadata_filename)
                
                # 使用新加密方式重新加密文件
                # 由于现在我们有不同类型的加密器，需要特殊处理
                with open(encrypted_file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # 根据原文件的加密方式创建对应的解密器
                old_encryption_method = file_info.get('encryption_method', 'AES')
                if old_encryption_method == 'STREAM':
                    old_cipher = StreamCipher(self.master_password)
                else:
                    old_cipher = AESCipher(self.master_password)
                
                try:
                    # 解密原文件
                    if old_encryption_method == 'STREAM':
                        # 对于流加密，我们需要流式解密到临时文件，然后重新加密
                        import tempfile
                        with tempfile.NamedTemporaryFile(delete=False) as temp_output:
                            temp_output_path = temp_output.name
                        
                        try:
                            old_cipher.decrypt_stream(encrypted_file_path, temp_output_path)
                            
                            # 读取解密后的内容
                            with open(temp_output_path, 'rb') as f:
                                decrypted_data = f.read()
                        finally:
                            # 删除临时解密文件
                            if os.path.exists(temp_output_path):
                                os.remove(temp_output_path)
                    else:  # AES
                        decrypted_data = old_cipher.decrypt(encrypted_data)
                    
                    # 获取元数据
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
                    
                    # 使用新加密方式加密文件内容
                    if new_encryption_method == 'STREAM':
                        new_cipher = StreamCipher(self.master_password)
                        # 使用流式加密到新文件
                        import tempfile
                        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
                            temp_input_path = temp_input.name
                        
                        try:
                            # 将解密数据写入临时文件
                            with open(temp_input_path, 'wb') as f:
                                f.write(decrypted_data)
                            
                            # 流式加密临时文件到目标文件
                            new_cipher.encrypt_stream(temp_input_path, new_encrypted_file_path)
                        finally:
                            # 删除临时输入文件
                            if os.path.exists(temp_input_path):
                                os.remove(temp_input_path)
                    else:  # AES
                        new_cipher = AESCipher(self.master_password)
                        new_encrypted_data = new_cipher.encrypt(decrypted_data)
                        
                        # 原子写入新的加密文件
                        temp_new_encrypted_path = new_encrypted_file_path + '.tmp'
                        with open(temp_new_encrypted_path, 'wb') as f:
                            f.write(new_encrypted_data)
                        # 原子重命名
                        os.replace(temp_new_encrypted_path, new_encrypted_file_path)
                    
                    # 创建新的加密元数据
                    new_metadata = {
                        "original_filename": original_filename,
                        "original_filepath": original_filepath,
                        "encrypted_filename": new_encrypted_filename,
                        "creation_time": creation_time,
                        "encryption_method": new_encryption_method  # 记录新的加密方式
                    }
                    
                    # 序列化新元数据并加密
                    new_metadata_json = json.dumps(new_metadata)
                    new_encrypted_metadata = new_cipher.encrypt(new_metadata_json.encode('utf-8'))
                    
                    # 原子写入新的加密元数据
                    temp_new_metadata_path = new_metadata_path + '.tmp'
                    with open(temp_new_metadata_path, 'wb') as f:
                        f.write(new_encrypted_metadata)
                    # 原子重命名
                    os.replace(temp_new_metadata_path, new_metadata_path)
                    
                    # 删除旧的加密文件和元数据文件
                    os.remove(encrypted_file_path)
                    if os.path.exists(metadata_path):
                        os.remove(metadata_path)
                except Exception as e:
                    print(f"重新加密文件失败 {encrypted_file_path}: {str(e)}")
                    # 继续处理下一个文件
                
                # 更新进度条
                progress['value'] = idx + 1
                progress_window.update()  # 更新窗口以刷新进度条
            
            # 在主线程中显示完成消息
            parent_window.after(0, lambda: messagebox.showinfo("完成", f"所有文件已重新加密为{new_encryption_method}格式！"))
            
            # 在主线程中刷新文件列表
            parent_window.after(0, self.refresh_file_list)
            
            # 在主线程中关闭进度窗口
            parent_window.after(0, progress_window.destroy)
            
        except Exception as e:
            # 在主线程中显示错误消息
            parent_window.after(0, lambda: messagebox.showerror("错误", f"重新加密过程中发生错误: {str(e)}"))
    
    def open_change_password(self, parent_window):
        """
        打开修改密码窗口
        """
        change_window = tk.Toplevel(parent_window)
        change_window.title("修改密码")
        change_window.geometry("400x350")
        
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
        
        # 进度条
        ttk.Label(main_frame, text="进度:").grid(row=4, column=0, sticky=tk.W, pady=5)
        progress = ttk.Progressbar(main_frame, length=200, mode='determinate')
        progress.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        # 确认按钮
        ttk.Button(button_frame, text="确认", command=lambda: self.change_password(
            old_password_var.get(), 
            new_password_var.get(), 
            confirm_new_password_var.get(), 
            change_window, 
            parent_window,
            progress
        )).grid(row=0, column=0, padx=5)
        
        # 取消按钮
        ttk.Button(button_frame, text="取消", command=change_window.destroy).grid(row=0, column=1, padx=5)
        
        # 配置列权重，使进度条可以扩展
        main_frame.columnconfigure(1, weight=1)
    
    def change_password(self, old_password, new_password, confirm_new_password, change_window, parent_window, progress_bar):
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
            
            # 配置进度条
            total_files = len(encrypted_files)
            if total_files > 0:
                progress_bar['maximum'] = total_files
                progress_bar['value'] = 0
                change_window.update()  # 更新窗口以显示进度条
            
            # 重新加密所有文件
            for idx, file_info in enumerate(encrypted_files):
                encrypted_file_path = file_info['encrypted_path']
                
                # 获取对应的元数据文件路径
                encrypted_filename = os.path.basename(encrypted_file_path)
                base_uuid = os.path.splitext(encrypted_filename)[0]  # 获取UUID部分
                metadata_filename = base_uuid + '.meta'
                metadata_path = os.path.join(os.path.dirname(encrypted_file_path), metadata_filename)
                
                # 生成新的混淆的文件名
                new_encrypted_filename = str(uuid.uuid4()) + '.llaes'
                new_encrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), new_encrypted_filename)
                
                # 生成新元数据文件路径
                new_base_uuid = os.path.splitext(new_encrypted_filename)[0]  # 获取新UUID部分
                new_metadata_filename = new_base_uuid + '.meta'
                new_metadata_path = os.path.join(os.path.dirname(encrypted_file_path), new_metadata_filename)
                
                # 使用分块方式重新加密文件
                reencrypt_file_chunked(
                    encrypted_file_path, 
                    old_password, 
                    new_encrypted_file_path, 
                    new_password, 
                    metadata_path, 
                    new_metadata_path
                )
                
                # 删除旧的加密文件和元数据文件
                os.remove(encrypted_file_path)
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
                
                # 更新进度条
                progress_bar['value'] = idx + 1
                change_window.update()  # 更新窗口以刷新进度条
                
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