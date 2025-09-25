# AES-128文件加密器 - 源码保护版

## 概述
这是一个具有源代码保护功能的AES-128文件加密器。源代码已被编译为字节码以防止直接查看和修改，同时保留了所有原始功能。

## 安全特性
- 源代码编译为字节码保护
- 不可直接查看核心算法实现
- 保持所有原始功能完整性
- 模块间依赖关系正常处理

## 文件说明

### 核心文件
- `run_encrypted.py` - 保护版启动器（推荐使用）
- `crypto_utils.pyc` - 加密工具模块字节码
- `password_manager.pyc` - 密码管理模块字节码  
- `main.pyc` - 主程序模块字节码

### 工具脚本
- `launcher.py` - 备用启动器
- `compile_src.py` - 源码编译脚本
- `create_executable.py` - 可执行文件创建脚本

### 备份文件
- `backup/` 目录 - 原始源代码备份

## 运行方法

### 方法1：直接运行（推荐）
```bash
python AESFileEncryptor/src/run_encrypted.py
```

### 方法2：使用备用启动器
```bash
python AESFileEncryptor/src/launcher.py
```

## 源码保护说明

### 保护方式
1. 原始源代码已编译为字节码文件
2. 源文件替换为占位符内容
3. 程序运行时从字节码加载模块

### 安全级别
- 防止非技术人员查看源码
- 防止简单修改程序逻辑
- 需要高级技能才可能逆向

### 功能完整性
- 所有原始功能完全保留
- 加密/解密算法正常工作
- 用户界面和交互正常
- 密码管理功能正常

## 系统要求
- Python 3.6+
- pycryptodome 库
- tkinter 库

## 安装依赖
```bash
pip install pycryptodome
```

## 开发和调试
如需修改源代码：
1. 从 `backup/` 目录恢复原始源文件
2. 进行修改和测试
3. 重新运行 `compile_src.py` 重新保护源码

## 部署建议
1. 仅部署以下文件：
   - `.pyc` 字节码文件
   - `run_encrypted.py` 启动器
   - 必要的库依赖
2. 不要部署 `backup/` 目录
3. 可使用 `create_executable.py` 创建独立可执行文件

## 版本信息
- 版本：2.0（源码保护版）
- 发布日期：2025年