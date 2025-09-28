import os
import sys
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def check_pyinstaller():
    # 检查是否安装了PyInstaller
    try:
        subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], 
                      capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_pyinstaller():
    # 安装PyInstaller，使用国内镜像源
    try:
        # 首先尝试使用国内镜像源安装
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller", "-i", "https://pypi.tuna.tsinghua.edu.cn/simple"], 
                      check=True)
        return True
    except subprocess.CalledProcessError:
        try:
            # 如果失败，尝试使用默认源
            subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], 
                          check=True)
            return True
        except subprocess.CalledProcessError:
            return False

def convert_to_exe(py_file_path, options=None):
    # 将Python文件转换为exe
    if options is None:
        options = []
    
    # 获取文件名和目录
    file_dir = os.path.dirname(py_file_path)
    file_name = os.path.basename(py_file_path)
    
    # 构建命令
    cmd = [sys.executable, "-m", "PyInstaller"]
    cmd.extend(options)
    cmd.append(file_name)
    
    # 执行转换
    try:
        result = subprocess.run(cmd, cwd=file_dir, capture_output=True, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

class PyToExeConverter:
    def __init__(self, root):
        self.root = root
        self.root.title("Python转EXE工具")
        self.root.geometry("600x400")
        
        self.py_file_path = tk.StringVar()
        
        self.create_widgets()
        
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(main_frame, text="选择Python文件", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Entry(file_frame, textvariable=self.py_file_path, width=50, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="浏览", command=self.browse_file).pack(side=tk.RIGHT, padx=(5, 0))
        
        # 选项区域
        options_frame = ttk.LabelFrame(main_frame, text="转换选项", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.one_file = tk.BooleanVar()
        self.one_dir = tk.BooleanVar(value=True)  # 默认为目录模式
        self.console = tk.BooleanVar()
        self.no_console = tk.BooleanVar()
        self.add_icon = tk.BooleanVar()
        
        ttk.Checkbutton(options_frame, text="打包为单个文件 (--onefile)", variable=self.one_file).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="打包为目录 (--onedir)", variable=self.one_dir).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="显示控制台窗口 (--console)", variable=self.console).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="不显示控制台窗口 (--noconsole)", variable=self.no_console).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="添加图标", variable=self.add_icon).pack(anchor=tk.W)
        
        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.convert_btn = ttk.Button(button_frame, text="转换为EXE", command=self.convert, state=tk.DISABLED)
        self.convert_btn.pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="退出", command=self.root.quit).pack(side=tk.RIGHT)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="转换日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, height=10)
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def browse_file(self):
        # 浏览Python文件
        file_path = filedialog.askopenfilename(
            title="选择Python文件",
            filetypes=[("Python Files", "*.py"), ("All Files", "*.*")]
        )
        
        if file_path:
            self.py_file_path.set(file_path)
            self.convert_btn.config(state=tk.NORMAL)
            
    def log_message(self, message):
        # 添加日志信息
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()
        
    def convert(self):
        # 执行转换
        # 检查是否安装了PyInstaller
        self.log_message("检查PyInstaller...")
        if not check_pyinstaller():
            self.log_message("PyInstaller未安装，正在安装...")
            if install_pyinstaller():
                self.log_message("PyInstaller安装成功")
            else:
                self.log_message("PyInstaller安装失败")
                messagebox.showerror("错误", "无法安装PyInstaller")
                return
        else:
            self.log_message("PyInstaller已安装")
            
        # 构建选项
        options = []
        
        # 处理文件打包选项
        if self.one_file.get():
            options.append("--onefile")
        if self.one_dir.get():
            options.append("--onedir")
            
        # 处理控制台选项
        if self.console.get():
            options.append("--console")
        if self.no_console.get():
            options.append("--noconsole")
            
        # 处理图标选项
        if self.add_icon.get():
            icon_path = filedialog.askopenfilename(
                title="选择图标文件",
                filetypes=[("Icon Files", "*.ico"), ("All Files", "*.*")]
            )
            if icon_path:
                options.extend(["--icon", icon_path])
            else:
                self.log_message("未选择图标文件")
                
        # 执行转换
        self.log_message("开始转换...")
        self.convert_btn.config(state=tk.DISABLED)
        
        success, output = convert_to_exe(self.py_file_path.get(), options)
        
        if success:
            self.log_message("转换成功!")
            self.log_message("输出信息:")
            self.log_message(output)
            messagebox.showinfo("成功", "Python文件已成功转换为exe文件")
        else:
            self.log_message("转换失败!")
            self.log_message("错误信息:")
            self.log_message(output)
            messagebox.showerror("错误", "转换过程中出现错误")
            
        self.convert_btn.config(state=tk.NORMAL)

def main():
    root = tk.Tk()
    app = PyToExeConverter(root)
    root.mainloop()

if __name__ == "__main__":
    main()