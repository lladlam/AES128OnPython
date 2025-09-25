"""
编译脚本 - 将源码编译为字节码并保护原文件
"""
import py_compile
import marshal
import os
import shutil
from pathlib import Path

# 定义源文件路径
SOURCE_DIR = "D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src"
BACKUP_DIR = os.path.join(SOURCE_DIR, "backup")

def compile_to_bytecode(source_path, bytecode_path):
    """
    将源码编译为字节码
    """
    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        code = compile(source_code, source_path, 'exec')
        
        with open(bytecode_path, 'wb') as f:
            marshal.dump(code, f)
        
        return True
    except Exception as e:
        print(f"编译失败 {source_path}: {e}")
        return False

def main():
    # 创建备份目录
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # 定义要编译的源文件
    source_files = [
        "crypto_utils.py",
        "password_manager.py", 
        "main.py"
    ]
    
    for filename in source_files:
        source_path = os.path.join(SOURCE_DIR, filename)
        bytecode_path = os.path.join(SOURCE_DIR, f"{os.path.splitext(filename)[0]}.pyc")
        
        if os.path.exists(source_path):
            # 备份原文件
            backup_path = os.path.join(BACKUP_DIR, filename)
            shutil.copy2(source_path, backup_path)
            print(f"已备份 {filename} 到 {backup_path}")
            
            # 编译为字节码
            if compile_to_bytecode(source_path, bytecode_path):
                print(f"已编译 {filename} 为字节码")
                
                # 将原文件内容替换为最小的导入代码
                with open(source_path, 'w', encoding='utf-8') as f:
                    f.write(f'''"""
加密的 {filename} 模块
原文件已编译为字节码
"""
# 加密模块 - 源码已被保护
''')
                print(f"已保护源文件 {filename}")
            else:
                print(f"编译失败 {filename}")
        else:
            print(f"源文件不存在: {source_path}")

    print("编译完成！")
    print("使用 launcher.py 启动程序")

if __name__ == "__main__":
    main()