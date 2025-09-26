# AES-128文件加密器 - 项目结构说明

## 项目概述

AES-128文件加密器的完整项目结构，包含源代码、文档和资源文件。

## 主要目录结构

```
AES128OnPython/
├── main.py                  # 主程序，包含所有代码          
├── docs/                  # 文档目录
│   ├── USER_GUIDE.md      # 详细用户指南
│   ├── QUICK_START.md     # 快速入门指南
│   ├── AES_TECHNICAL.md   # AES技术说明
│   ├── PYTHON_REQUIREMENTS.md # Python依赖说明
│   ├── INSTALLATION.md    # 安装和运行说明
│   └── SECURE_README.md   # 源码保护版说明
├── requirements.txt       # Python依赖列表
└──  README.md          # 主要使用说明
```

## 详细目录说明

### src/ 目录 - 源代码文件
- **main.py**: 主程序文件，包含GUI界面实现和主要业务逻辑
  - AESCipher类：AES加密解密实现
  - encrypt_file(): 文件加密函数
  - decrypt_file(): 文件解密函数
  - view_encrypted_file(): 查看加密文件内容函数
  - get_encrypted_files_list(): 获取加密文件列表函数
  - save_password(): 保存加密密码
  - verify_password(): 验证密码
  - is_password_set(): 检查密码是否已设置
  - clear_data_folder(): 清空数据文件夹

### Data/ 目录 - 加密文件存储
- 存储所有加密后的文件（.llaes格式）
- 存储对应的元数据文件（.meta格式，加密存储原始文件名等信息）
- 可能包含多个子目录（如果用户选择了不同的加密目录）

### docs/ 目录 - 文档文件
- **README.md**: 项目主文档，功能介绍和基本使用
- **USER_GUIDE.md**: 详细用户手册
- **QUICK_START.md**: 快速入门指南
- **AES_TECHNICAL.md**: AES加密算法技术说明
- **PYTHON_REQUIREMENTS.md**: Python运行库需求说明
- **INSTALLATION.md**: 安装和运行详细说明

## 文件扩展名说明

- **.py**: Python源代码文件
- **.pyc**: 编译后的Python字节码文件
- **.llaes**: 加密文件扩展名
- **.meta**: 加密元数据文件（存储原始文件名等信息）
- **.md**: Markdown格式文档文件
- **.txt**: 文本文件

## 配置文件

### requirements.txt
```
pycryptodome>=3.10.1
```
定义了项目运行所需的Python库及其版本要求。

## 依赖关系

```
main.py
├── crypto_utils.py (加密解密功能)
├── password_manager.py (密码管理)
├── pycryptodome (加密算法)
└── tkinter (Python内置GUI库)

运行时依赖：
├── Python 3.6+
├── pycryptodome
└── tkinter
```

## 运行时目录结构

当程序运行时，会根据需要创建以下结构：

```
AES128OnPython/
├── main.py
├── Data/ (或用户指定的其他目录)  # 现在加密文件存储在此目录下
├── docs/
├── [临时文件] (系统Temp目录中的临时解密文件)
└── password.pwd (加密存储的密码文件，在Data目录中，文件名混淆)
```

## 安全相关文件

- 加密后的密码文件存储在Data目录中，文件名被混淆
- 加密文件使用.llaes扩展名，内容为AES加密的原始文件
- 元数据文件(.meta)存储加密的原始文件名等信息
- 临时解密文件在系统Temp目录中，会在指定时间后自动删除

## 可扩展性

项目结构设计支持以下扩展：
- 添加新的加密算法支持
- 增加云存储功能
- 扩展文件格式支持
- 添加批量处理功能
- 集成更多安全特性
