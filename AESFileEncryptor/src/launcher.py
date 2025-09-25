"""
AES-128文件加密器启动器
使用字节码加载加密的源代码
"""
import py_compile
import marshal
import os
import sys
import tempfile
import importlib.util

# 定义项目结构
MODULES = {
    'crypto_utils': 'D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src\\crypto_utils.py',
    'password_manager': 'D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src\\password_manager.py',
    'main': 'D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src\\main.py'
}

def compile_to_bytecode(source_path, bytecode_path):
    """
    将源码编译为字节码
    """
    try:
        py_compile.compile(source_path, bytecode_path, doraise=True)
        return True
    except Exception as e:
        print(f"编译失败 {source_path}: {e}")
        return False

def save_bytecode_compact(source_path, bytecode_path):
    """
    以更紧凑的方式保存字节码
    """
    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        code = compile(source_code, source_path, 'exec')
        
        with open(bytecode_path, 'wb') as f:
            marshal.dump(code, f)
        
        return True
    except Exception as e:
        print(f"保存字节码失败 {source_path}: {e}")
        return False

def load_bytecode(bytecode_path):
    """
    从字节码文件加载代码
    """
    with open(bytecode_path, 'rb') as f:
        code = marshal.load(f)
    return code

def import_from_bytecode(name, bytecode_path):
    """
    从字节码文件动态导入模块
    """
    # 加载字节码
    code = load_bytecode(bytecode_path)
    
    # 创建模块
    module = type(sys)(name)
    module.__file__ = bytecode_path
    
    # 执行字节码
    exec(code, module.__dict__)
    
    return module

def main():
    """
    主函数
    """
    print("AES-128文件加密器 - 安全启动")
    
    # 创建临时目录存放字节码文件
    temp_dir = tempfile.mkdtemp(prefix='aes_encrypted_')
    
    try:
        # 编译所有模块为字节码
        bytecode_files = {}
        for name, src_path in MODULES.items():
            bytecode_path = os.path.join(temp_dir, f"{name}.pyc")
            if save_bytecode_compact(src_path, bytecode_path):
                bytecode_files[name] = bytecode_path
                print(f"已编译模块: {name}")
            else:
                print(f"编译失败: {name}")
                return
        
        # 导入加密工具模块
        crypto_utils = import_from_bytecode('crypto_utils', bytecode_files['crypto_utils'])
        password_manager = import_from_bytecode('password_manager', bytecode_files['password_manager'])
        
        # 设置模块到sys中，以便main模块可以导入
        sys.modules['crypto_utils'] = crypto_utils
        sys.modules['password_manager'] = password_manager
        
        # 导入并运行主模块
        main_module = import_from_bytecode('main', bytecode_files['main'])
        
        # 运行主函数
        if hasattr(main_module, 'main'):
            main_module.main()
        else:
            print("错误: 找不到主函数")
    
    except Exception as e:
        print(f"运行时错误: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # 清理临时文件
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()