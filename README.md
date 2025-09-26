<img src="https://count.i80k.com/api/counter?name=AES128OnPython&theme=rule34&length=7&scale=1&offset=0&align=center&pixelate=on&darkmode=auto" alt="AES128OnPython" />

# AES128OnPython
基于Python的AES加密器，可以直接加密解密并且在软件内查看加密的文件
# AES-128文件加密器

## 项目概述

AES-128文件加密器是一款使用AES-128算法对文件进行加密和解密的安全工具。它提供友好的图形用户界面，支持加密任意类型的文件，解密已加密的文件，并能直接查看加密文件的内容。

## 主要功能

- 🔐 **高强度加密**：使用AES-128算法进行文件加密
- 🔓 **安全解密**：将加密文件恢复为原始文件
- 👁️ **内容查看**：临时解密查看文件内容（不解密到用户目录）
- 📁 **多目录支持**：可在任意目录中进行加密操作
- 🔐 **统一密码管理**：一次设置，多次使用
- 🗂️ **文件名混淆**：加密后使用UUID文件名保护隐私

## 目录结构

```
AESFileEncryptor/
├── src/                    # 源代码
│   └── main.py            # 主程序
├── docs/                  # 文档
│   ├── README.md          # 本文件
│   ├── USER_GUIDE.md      # 用户指南
│   ├── INSTALLATION.md    # 安装说明
│   └── ...                # 其他文档
└── requirements.txt       # 依赖列表
```

## 安装和运行

### 1. 安装依赖
```bash
pip install -r AESFileEncryptor/requirements.txt
# 或单独安装
pip install pycryptodome
```

### 2. 运行程序
```bash
python AESFileEncryptor/src/main.py
```

### 3. 无控制台窗口运行（Windows）
```bash
pythonw AESFileEncryptor/src/main.py
```

## 快速使用

1. **首次使用**：设置主密码
2. **选择目录**：点击"选择加密目录"（可选）
3. **加密文件**：点击"添加文件"选择并加密
4. **解密文件**：选择加密文件，点击"解密文件"
5. **查看内容**：选择加密文件，点击"查看内容"

## 安全特性

- 所有加密操作在本地进行
- 密码使用哈希算法安全存储
- 加密文件名混淆保护隐私
- 临时解密文件自动清理
- 源代码经过保护防止篡改

## 系统要求

- Python 3.6 或更高版本
- pycryptodome 库
- tkinter 库（通常随Python一起安装）

## 文档

- [用户指南](docs/USER_GUIDE.md) - 详细使用说明
- [安装说明](docs/INSTALLATION.md) - 完整安装指南  
- [Python依赖](docs/PYTHON_REQUIREMENTS.md) - 运行库需求
- [技术说明](docs/AES_TECHNICAL.md) - 加密算法技术
- [项目结构](docs/PROJECT_STRUCTURE.md) - 目录结构说明

## 版本信息

- **版本**：2.3.0 beta1
- **发布日期**：2025年
- **功能**：加密/解密/查看 + 源码保护 + 多目录支持 + 自动删除 + 密码修改

## 新功能 (v2.3.0 beta1)

- 🗂️ **自动Data文件夹管理**：程序启动时自动检查并创建Data文件夹
- 🧹 **自动清理**：解密后自动删除加密文件和元数据文件
- 🔑 **密码修改**：用户可在设置中安全修改主密码
- 📁 **统一存储位置**：所有加密文件存储在main.py同目录下的Data文件夹

## 许可证

本项目使用GPL-3.0-or-later许可证，欢迎贡献和改进。

---
*一个安全、易用、功能完整的文件加密解决方案*
