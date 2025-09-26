# AES-128文件加密器 - 安装和运行说明

## 系统要求

### 操作系统
- Windows 7 或更高版本
- macOS 10.12 或更高版本  
- Linux (支持tkinter的发行版)

### 硬件要求
- CPU：支持AES指令集的现代处理器（推荐）
- 内存：至少512MB可用RAM（推荐2GB或更多）
- 存储：至少50MB可用空间

## Python环境要求

### Python版本
- **最低要求**：Python 3.6
- **推荐版本**：Python 3.8 或更高版本
- **不支持**：Python 2.x

### 验证Python安装
在命令行中运行以下命令验证Python版本：
```bash
python --version
```
或
```bash
python3 --version
```

## 依赖库安装

### 自动安装（推荐）
1. 打开命令行/终端
2. 导航到项目根目录：
   ```bash
   cd D:\Qwen\DataAES128_byPython\AESFileEncryptor
   ```
3. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
   
### 手动安装
如果自动安装失败，可以手动安装：
```bash
pip install pycryptodome
```

## 特定操作系统安装指南

### Windows
1. 下载并安装Python（从 https://www.python.org/downloads/）
   - 确保勾选 "Add Python to PATH"
   - 建议安装最新版本的Python 3.x

2. 验证安装：
   ```cmd
   python --version
   pip --version
   ```

3. 安装依赖：
   ```cmd
   pip install pycryptodome
   ```

### macOS
1. 安装Python（如果未安装）：
   ```bash
   # 使用Homebrew
   brew install python3
   ```

2. 安装依赖：
   ```bash
   pip3 install pycryptodome
   ```

### Linux (Ubuntu/Debian)
1. 安装Python和tkinter：
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-tk
   ```

2. 安装依赖：
   ```bash
   pip3 install pycryptodome
   ```

### Linux (CentOS/RHEL/Fedora)
1. 安装Python和tkinter：
   ```bash
   # CentOS/RHEL
   sudo yum install python3 python3-pip tkinter
   # 或 Fedora
   sudo dnf install python3 python3-pip python3-tkinter
   ```

2. 安装依赖：
   ```bash
   pip3 install pycryptodome
   ```

## 运行软件

### 标准运行（显示控制台）
```bash
python AESFileEncryptor/src/main.py
```

### GUI模式运行（无控制台窗口，Windows）
```bash
pythonw AESFileEncryptor/src/main.py
```

### 在虚拟环境中运行（推荐）
```bash
# 创建虚拟环境
python -m venv aes_env

# 激活虚拟环境
# Windows:
aes_env\Scripts\activate
# Linux/macOS:
source aes_env/bin/activate

# 安装依赖
pip install -r AESFileEncryptor/requirements.txt

# 运行软件
python AESFileEncryptor/src/main.py

# 使用完毕后退出虚拟环境
deactivate
```

## 常见问题解决

### 问题1：'pip' 不是内部或外部命令
**解决方案**：
- 确保Python安装时勾选了 "Add Python to PATH"
- 或使用 `python -m pip` 替代 `pip`

### 问题2：Permission Denied 或 Access Denied
**解决方案**：
- Windows：以管理员身份运行命令提示符
- Linux/macOS：使用 `pip install --user` 或虚拟环境

### 问题3：tkinter not found
**解决方案**：
- Windows：重新安装Python，确保包含tkinter
- Linux：安装tkinter包（如上安装指南所示）

### 问题4：pycryptodome安装失败
**解决方案**：
```bash
# 尝试升级pip
python -m pip install --upgrade pip

# 尝试使用预编译版本
pip install --only-binary=all pycryptodome

# 或尝试安装wheel
pip install wheel
pip install pycryptodome
```

### 问题5：GUI界面不显示
**解决方案**：
- 确保系统有图形界面环境
- 在Linux上，可能需要设置DISPLAY环境变量
- 检查防火墙是否阻止了GUI应用

## 验证安装

安装完成后，可以通过以下命令验证：

```bash
# 验证Python版本
python --version

# 验证依赖库
python -c "from Crypto.Cipher import AES; print('pycryptodome OK')"
python -c "import tkinter; print('tkinter OK')"

# 尝试导入所有依赖
python -c "
import os, sys, json, time, tempfile, uuid, hashlib, ctypes, shutil, importlib, marshal, base64, binascii
from Crypto.Cipher import AES
import tkinter
print('所有依赖验证通过！')
"
```

## 性能优化建议

- 对于大文件加密/解密，确保系统有足够内存
- 使用SSD存储可以提高性能
- 关闭不必要的后台程序以释放资源

## 安全注意事项

- 程序的所有加密操作都在本地进行
- 请妥善保管您的主密码
- 不要在不安全的网络环境中传输加密文件
- 定期备份您的加密文件和密码

## 支持

如果遇到问题，请检查：
1. Python版本是否符合要求
2. 所有依赖是否正确安装
3. 系统是否满足硬件要求
4. 防火墙或安全软件是否阻止程序运行

## 版本信息

- **当前版本**：V2.3.0-beta3
- **发布日期**：2025年
- **主要更新**：
  - 自动创建Data文件夹
  - 解密后自动删除加密文件
  - 新增修改密码功能
  - Data目录位置调整至main.py同目录