# AES-128文件加密器 - Python运行库需求说明

## 概述
本文档详细列出了AES-128文件加密器运行所需的Python库及其版本要求。

## 基础要求
- Python版本：3.6或更高版本

## 必需库列表

### 1. 加密库
- **pycryptodome**
  - 版本：>=3.10.1
  - 功能：提供AES加密算法实现
  - 安装命令：`pip install pycryptodome`
  - 用途：实现AES-128加密/解密算法

### 2. GUI界面库
- **tkinter**
  - 版本：Python内置
  - 功能：提供图形用户界面
  - 用途：构建用户交互界面
  - 注意：在大多数Python发行版中已预装

### 3. 操作系统库
- 以下库均为Python标准库，无需额外安装：
  - os：文件和目录操作
  - json：JSON数据处理
  - time：时间处理
  - tempfile：临时文件管理
  - uuid：生成唯一标识符
  - hashlib：哈希算法
  - ctypes：系统API调用
  - shutil：高级文件操作
  - sys：系统相关参数和函数
  - importlib：动态导入模块
  - marshal：序列化Python对象
  - base64：Base64编码/解码
  - binascii：二进制与ASCII转换

## 安装步骤

### 方法1：逐个安装
```bash
pip install pycryptodome
```

### 方法2：使用requirements.txt
创建一个名为 `requirements.txt` 的文件，内容如下：
```
pycryptodome>=3.10.1
```

然后运行：
```bash
pip install -r requirements.txt
```

## 验证安装

运行以下Python代码来验证所有依赖是否正确安装：

```python
# 验证基础库
import os, json, time, tempfile, uuid, hashlib, ctypes, shutil, sys, importlib, marshal
print("基础库验证通过")

# 验证tkinter
import tkinter as tk
root = tk.Tk()
root.destroy()
print("tkinter验证通过")

# 验证加密库
from Crypto.Cipher import AES
print("pycryptodome验证通过")

print("所有依赖验证通过！")
```

## 可能遇到的问题和解决方案

### 1. pycryptodome安装失败
**问题**：在某些系统上安装pycryptodome可能失败
**解决方案**：
  - 确保已安装Microsoft Visual C++ Build Tools（Windows）
  - 或尝试：`pip install --upgrade pip`
  - 或使用预编译版本：`pip install --only-binary=all pycryptodome`

### 2. tkinter不可用
**问题**：在某些精简版Python安装中tkinter不可用
**解决方案**：
  - 重新安装完整版Python
  - 确保安装时选择了tcl/tk和tkinter

### 3. 权限问题
**问题**：在系统Python环境中安装时出现权限错误
**解决方案**：
  - 使用虚拟环境：`python -m venv myenv` 然后 `myenv\Scripts\activate`
  - 或使用用户安装：`pip install --user pycryptodome`

## 虚拟环境推荐

为避免依赖冲突，建议使用虚拟环境：

```bash
# 创建虚拟环境
python -m venv aes_encryptor_env

# 激活虚拟环境
# Windows:
aes_encryptor_env\Scripts\activate
# Linux/Mac:
source aes_encryptor_env/bin/activate

# 安装依赖
pip install pycryptodome

# 运行软件
python AESFileEncryptor/src/main.py

# 退出虚拟环境
deactivate
```

## 版本兼容性

| 库名称 | 最低版本 | 推荐版本 | Python版本要求 |
|--------|----------|----------|----------------|
| pycryptodome | 3.10.1 | 最新稳定版 | 3.6+ |
| tkinter | 内置 | 内置 | 3.6+ |

## 可选优化库（推荐安装）

### 1. psutil (系统信息)
- 版本：任意版本
- 安装：`pip install psutil`
- 用途：更精确的内存监控（如果安装了则使用，未安装则使用系统API）

## 常见环境配置

### Windows
1. 安装Python 3.6+
2. 打开命令提示符
3. 运行：`pip install pycryptodome`
4. 运行软件：`python AESFileEncryptor/src/main.py`

### Linux
1. 安装Python 3.6+
2. 安装tkinter（如果未包含）：
   - Ubuntu/Debian: `sudo apt-get install python3-tk`
   - CentOS/RHEL: `sudo yum install tkinter` 或 `sudo dnf install python3-tkinter`
3. 安装依赖：`pip install pycryptodome`
4. 运行软件：`python3 AESFileEncryptor/src/main.py`

### macOS
1. 安装Python 3.6+
2. 安装依赖：`pip install pycryptodome`
3. 运行软件：`python AESFileEncryptor/src/main.py`

## 故障排除

### 问题1：`ModuleNotFoundError: No module named 'Crypto'`
**解决方案**：运行 `pip install pycryptodome`

### 问题2：`No module named '_tkinter'`
**解决方案**：重新安装Python，确保包含tkinter组件

### 问题3：GUI界面无法显示
**解决方案**：
- 检查是否有图形界面环境
- 在Linux上可能需要安装X11转发
- 确保显示设置正确

## 安全说明

- pycryptodome库提供工业级加密算法
- 所有加密操作都在本地进行，不涉及网络传输
- 密码不会以明文形式存储

## 性能优化建议

- 使用最新版本的pycryptodome以获得最佳性能
- 在内存充足的系统上，临时文件处理会更高效
- 避免同时处理过多大文件

## 版本信息

- **当前版本**：2.3.0 beta1
- **发布日期**：2025年
- **依赖库更新**：无变化
- **新增功能对依赖的影响**：新增的自动创建Data文件夹、解密后自动删除、修改密码功能均使用现有库实现，无额外依赖