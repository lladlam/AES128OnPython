"""
AES-128文件加密器 - 优化版启动器
使用预编译的字节码文件运行程序
"""
import os
import sys
import marshal
from pathlib import Path

def load_module_from_bytecode(module_name, bytecode_path):
    """
    从字节码文件加载模块
    """
    if not os.path.exists(bytecode_path):
        raise FileNotFoundError(f"字节码文件不存在: {bytecode_path}")
    
    with open(bytecode_path, 'rb') as f:
        code = marshal.load(f)
    
    # 创建模块对象
    import types
    module = types.ModuleType(module_name)
    module.__file__ = bytecode_path
    
    # 执行字节码
    exec(code, module.__dict__)
    
    return module

def setup_environment():
    """
    设置运行环境
    """
    src_dir = "D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src"
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

def main():
    """
    主函数 - 运行加密的程序
    """
    setup_environment()
    
    src_dir = "D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src"
    
    try:
        # 加载加密工具模块
        crypto_utils_path = os.path.join(src_dir, "crypto_utils.pyc")
        password_manager_path = os.path.join(src_dir, "password_manager.pyc")
        main_path = os.path.join(src_dir, "main.pyc")
        
        # 加载模块
        crypto_utils = load_module_from_bytecode('crypto_utils', crypto_utils_path)
        password_manager = load_module_from_bytecode('password_manager', password_manager_path)
        
        # 将模块添加到sys.modules，以便可以被其他模块导入
        sys.modules['crypto_utils'] = crypto_utils
        sys.modules['password_manager'] = password_manager
        
        # 加载并运行主模块
        main_module = load_module_from_bytecode('main', main_path)
        
        # 运行程序
        main_module.main()
        
    except Exception as e:
        print(f"程序运行错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()