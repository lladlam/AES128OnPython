"""
密码管理模块
"""
import os
import json
import uuid
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Data目录路径
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'Data')
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
    # 检查Data目录中是否存在.meta文件，这表明设置了密码
    if os.path.exists(DATA_DIR):
        for filename in os.listdir(DATA_DIR):
            if filename.endswith('.meta'):
                return True
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