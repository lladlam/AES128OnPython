"""创建可执行文件的打包脚本"""
import os
import sys

def create_spec_file():
    \"\"\"
    创建PyInstaller spec文件
    \"\"\"
    spec_content = '''# AES-128文件加密器打包配置

# 不需要包含源文件，因为我们将使用字节码运行器
a = Analysis(
    ['run_encrypted.py'],
    pathex=['D:/Qwen/DataAES128_byPython/AESFileEncryptor/src'],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AESFileEncryptor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 设置为False以创建GUI应用
    disable_windowed_tracker=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # 可以指定图标文件路径
)
'''
    with open("D:/Qwen/DataAES128_byPython/AESFileEncryptor/src/AESFileEncryptor.spec", "w", encoding="utf-8") as f:
        f.write(spec_content)
    print("已创建 spec 文件")

def main():
    print("开始创建可执行文件...")
    
    # 检查是否安装了PyInstaller
    try:
        import PyInstaller
        print("PyInstaller 已安装")
    except ImportError:
        print("请先安装 PyInstaller: pip install pyinstaller")
        return
    
    # 创建 spec 文件
    create_spec_file()
    
    # 运行 PyInstaller
    os.system("cd /D \"D:\\Qwen\\DataAES128_byPython\\AESFileEncryptor\\src\" && pyinstaller AESFileEncryptor.spec")
    
    print("打包完成！可执行文件位于 dist 文件夹中")

if __name__ == "__main__":
    main()