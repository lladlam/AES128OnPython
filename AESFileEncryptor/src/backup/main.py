"""
AES文件加密软件主程序
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from crypto_utils import encrypt_file, decrypt_file, view_encrypted_file, get_encrypted_files_list
from password_manager import save_password, verify_password, is_password_set, clear_data_folder
import time


class PasswordSetupApp:
    """
    密码设置界面
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("设置主密码")
        self.root.geometry("400x200")
        self.setup_ui()
    
    def setup_ui(self):
        """
        设置用户界面
        """
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="请设置主密码", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 密码输入
        ttk.Label(main_frame, text="设置密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=25)
        self.password_entry.grid(row=1, column=1, pady=5)
        
        # 确认密码
        ttk.Label(main_frame, text="确认密码:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(main_frame, textvariable=self.confirm_password_var, show="*", width=25)
        self.confirm_password_entry.grid(row=2, column=1, pady=5)
        
        # 按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="确定", command=self.set_password).grid(row=0, column=0, padx=5)
    
    def set_password(self):
        """
        设置密码
        """
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
        if not password:
            messagebox.showerror("错误", "请输入密码")
            return
        
        if password != confirm_password:
            messagebox.showerror("错误", "两次输入的密码不一致")
            return
        
        if len(password) < 6:
            messagebox.showerror("错误", "密码长度至少为6位")
            return
        
        try:
            # 保存密码
            save_password(password)
            messagebox.showinfo("成功", "密码设置成功！")
            # 关闭设置窗口并打开主程序
            self.root.destroy()
            main_app_root = tk.Tk()
            app = FileEncryptionApp(main_app_root, password)  # 传递主密码
            main_app_root.mainloop()
        except Exception as e:
            messagebox.showerror("错误", f"设置密码时发生错误: {str(e)}")


class PasswordVerificationApp:
    """
    密码验证界面
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("验证主密码")
        self.root.geometry("400x150")
        self.setup_ui()
    
    def setup_ui(self):
        """
        设置用户界面
        """
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="请输入主密码", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 密码输入
        ttk.Label(main_frame, text="密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="*", width=25)
        self.password_entry.grid(row=1, column=1, pady=5)
        self.password_entry.bind('<Return>', lambda event: self.verify_password())  # 回车键确认
        
        # 按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="确定", command=self.verify_password).grid(row=0, column=0, padx=5)
        
        # 设置焦点到密码输入框
        self.password_entry.focus()
    
    def verify_password(self):
        """
        验证密码
        """
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("错误", "请输入密码")
            return
        
        if verify_password(password):
            messagebox.showinfo("成功", "密码验证成功！")
            # 关闭验证窗口并打开主程序
            self.root.destroy()
            main_app_root = tk.Tk()
            app = FileEncryptionApp(main_app_root, password)  # 传递主密码
            main_app_root.mainloop()
        else:
            messagebox.showerror("错误", "密码错误，请重试")
            self.password_var.set("")  # 清空输入框
            self.password_entry.focus()  # 重新聚焦到输入框


class FileEncryptionApp:
    """
    文件加密软件主界面
    """
    
    def __init__(self, root, master_password):
        self.root = root
        self.root.title("AES-128文件加密器")
        self.root.geometry("800x600")
        
        # 存储主密码
        self.master_password = master_password
        
        # 当前选中的加密文件
        self.selected_encrypted_file = None
        
        self.setup_ui()
        # 刷新文件列表
        self.refresh_file_list()
    
    def setup_ui(self):
        """
        设置用户界面
        """
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="AES-128文件加密器", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=4, pady=10)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=5)
        
        # 添加文件按钮
        self.add_file_btn = ttk.Button(button_frame, text="添加文件", command=self.add_file)
        self.add_file_btn.grid(row=0, column=0, padx=5)
        
        # 解密按钮
        self.decrypt_btn = ttk.Button(button_frame, text="解密文件", command=self.decrypt_selected_file)
        self.decrypt_btn.grid(row=0, column=1, padx=5)
        
        # 查看加密文件内容按钮
        self.view_btn = ttk.Button(button_frame, text="查看内容", command=self.view_selected_file)
        self.view_btn.grid(row=0, column=2, padx=5)
        
        # 刷新列表按钮
        self.refresh_btn = ttk.Button(button_frame, text="刷新列表", command=self.refresh_file_list)
        self.refresh_btn.grid(row=0, column=3, padx=5)
        
        # 创建文件列表区域
        list_frame = ttk.LabelFrame(main_frame, text="加密文件列表", padding="5")
        list_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # 创建文件列表
        columns = ("原文件名", "加密文件名", "大小", "修改时间")
        self.file_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        # 设置列标题
        self.file_tree.heading("原文件名", text="原文件名")
        self.file_tree.heading("加密文件名", text="加密文件名")
        self.file_tree.heading("大小", text="大小")
        self.file_tree.heading("修改时间", text="修改时间")
        
        # 设置列宽
        self.file_tree.column("原文件名", width=150)
        self.file_tree.column("加密文件名", width=150)
        self.file_tree.column("大小", width=100)
        self.file_tree.column("修改时间", width=150)
        
        # 滚动条
        tree_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.file_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # 绑定选择事件
        self.file_tree.bind("<<TreeviewSelect>>", self.on_file_select)
        
        # 配置列表框架的权重
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # 结果显示区域
        ttk.Label(main_frame, text="操作结果:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        self.result_text = scrolledtext.ScrolledText(main_frame, width=90, height=12)
        self.result_text.grid(row=4, column=0, columnspan=4, pady=5)
        
        # 配置主框架权重以支持窗口缩放
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)  # 文件列表行可扩展
        main_frame.rowconfigure(4, weight=1)  # 结果区域行可扩展
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def refresh_file_list(self):
        """
        刷新加密文件列表
        """
        # 清空当前列表
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        try:
            # 使用主密码获取加密文件列表
            encrypted_files = get_encrypted_files_list(self.master_password)
            
            # 添加到列表中
            for file_info in encrypted_files:
                # 格式化文件大小
                size_str = f"{file_info['size']} 字节"
                if file_info['size'] > 1024:
                    size_str = f"{file_info['size']/1024:.1f} KB"
                if file_info['size'] > 1024*1024:
                    size_str = f"{file_info['size']/(1024*1024):.1f} MB"
                
                # 格式化修改时间
                mod_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_info['mod_time']))
                
                # 添加到列表
                self.file_tree.insert("", "end", values=(
                    file_info['original_name'],
                    file_info['encrypted_name'],
                    size_str,
                    mod_time_str
                ), tags=(file_info['encrypted_path'],))  # 将完整路径存储在tags中
        except Exception as e:
            messagebox.showerror("错误", f"获取文件列表失败: {str(e)}")
    
    def on_file_select(self, event):
        """
        当在列表中选择文件时触发
        """
        selection = self.file_tree.selection()
        if selection:
            item = self.file_tree.item(selection[0])
            # 从tags中获取加密文件的完整路径
            if item['tags']:
                self.selected_encrypted_file = item['tags'][0]
    
    def add_file(self):
        """
        添加文件并加密
        """
        file_path = filedialog.askopenfilename(
            title="选择要加密的文件",
            filetypes=[
                ("所有文件", "*.*"),
                ("文本文件", "*.txt"),
                ("图片文件", "*.jpg *.jpeg *.png *.gif"),
                ("PDF文件", "*.pdf")
            ]
        )
        
        if not file_path:
            return
        
        # 使用主密码加密文件
        self.encrypt_file_with_master_password(file_path)
    
    def decrypt_selected_file(self):
        """
        解密选中的加密文件
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return
        
        try:
            # 获取加密文件的原始文件名
            import json
            from crypto_utils import get_encrypted_files_list
            
            # 获取当前文件的信息
            all_files = get_encrypted_files_list(self.master_password)
            current_file_info = None
            for file_info in all_files:
                if file_info['encrypted_path'] == self.selected_encrypted_file:
                    current_file_info = file_info
                    break
            
            # 获取原始文件名
            original_name = current_file_info['original_name'] if current_file_info else "decrypted_file"
            
            # 让用户选择保存位置和文件名
            save_path = filedialog.asksaveasfilename(
                title="选择解密文件保存位置",
                defaultextension=os.path.splitext(original_name)[1] or ".*",
                initialfile=original_name,
                filetypes=[
                    ("所有文件", "*.*"),
                    ("文本文件", "*.txt"),
                    ("图片文件", "*.jpg *.jpeg *.png *.gif"),
                    ("PDF文件", "*.pdf")
                ]
            )
            
            if not save_path:
                return  # 用户取消了操作
            
            # 使用主密码解密文件到用户选择的位置
            from crypto_utils import decrypt_file
            final_path = decrypt_file(
                self.selected_encrypted_file, 
                self.master_password,
                output_dir=os.path.dirname(save_path),
                output_filename=os.path.basename(save_path)
            )
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "解密成功！\n")
            self.result_text.insert(tk.END, f"加密文件: {os.path.basename(self.selected_encrypted_file)}\n")
            self.result_text.insert(tk.END, f"解密后文件: {final_path}\n")
            
            messagebox.showinfo("成功", f"文件已解密!\n解密文件路径: {final_path}")
            
            # 刷新文件列表
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("解密失败", f"发生错误: {str(e)}")
    
    def view_selected_file(self):
        """
        查看选中的加密文件内容（通过临时解密到系统Temp文件夹）
        """
        if not self.selected_encrypted_file:
            messagebox.showwarning("警告", "请先从列表中选择一个加密文件")
            return
        
        import tempfile
        import time
        
        try:
            # 获取加密文件的原始文件名用于生成混淆的临时文件名
            import json
            from crypto_utils import get_encrypted_files_list
            
            # 获取当前文件的信息
            all_files = get_encrypted_files_list(self.master_password)
            current_file_info = None
            for file_info in all_files:
                if file_info['encrypted_path'] == self.selected_encrypted_file:
                    current_file_info = file_info
                    break
            
            # 获取原始文件名
            original_name = current_file_info['original_name'] if current_file_info else "temp_file"
            
            # 生成混淆的临时文件名：当前时间 + 混淆的原文件名
            timestamp = str(int(time.time() * 1000))  # 毫秒级时间戳
            temp_filename = f"{timestamp}_{original_name}"
            
            # 使用主密码解密文件到系统Temp文件夹，使用混淆的文件名
            from crypto_utils import decrypt_file
            temp_file_path = decrypt_file(
                self.selected_encrypted_file, 
                self.master_password,
                output_dir=tempfile.gettempdir(),
                output_filename=temp_filename
            )
            
            # 尝试用系统默认程序打开临时文件
            os.startfile(temp_file_path)  # Windows系统
            
            # 启动后台线程或计时器来稍后删除临时文件
            # 这里简单地使用一个计时器，等待一段时间后自动删除文件
            self.root.after(10000, lambda: self._delete_temp_file(temp_file_path))  # 10秒后删除
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"文件已临时解密到: {temp_file_path}\n")
            self.result_text.insert(tk.END, "文件将在10秒后自动删除。\n")
            
        except Exception as e:
            messagebox.showerror("查看失败", f"发生错误: {str(e)}")
    
    def _delete_temp_file(self, file_path):
        """
        删除临时文件
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                self.result_text.insert(tk.END, f"\n临时文件已删除: {file_path}")
        except Exception as e:
            # 如果删除失败，通常是因为用户已经手动删除了文件或权限问题
            pass
    
    def encrypt_file_with_master_password(self, file_path):
        """
        使用主密码加密文件
        """
        if not file_path:
            messagebox.showerror("错误", "请选择要加密的文件")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("错误", "所选文件不存在")
            return
        
        try:
            # 执行加密（使用主密码）
            encrypted_file_path = encrypt_file(file_path, self.master_password)
            
            # 在结果区域显示信息
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "加密成功！\n")
            self.result_text.insert(tk.END, f"原文件: {file_path}\n")
            self.result_text.insert(tk.END, f"加密后文件: {os.path.basename(encrypted_file_path)}\n")
            self.result_text.insert(tk.END, f"\n注意: 加密后的文件已存储到Data文件夹中，并使用了混淆文件名\n")
            
            messagebox.showinfo("成功", f"文件已加密!\n加密文件名: {os.path.basename(encrypted_file_path)}")
            
            # 刷新文件列表
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("加密失败", f"发生错误: {str(e)}")


def main():
    """
    主程序入口
    """
    if not is_password_set():
        # 如果未设置密码或密码文件被删除，则清空Data文件夹并显示设置界面
        clear_data_folder()
        root = tk.Tk()
        app = PasswordSetupApp(root)
        root.mainloop()
    else:
        # 如果已设置密码，则显示密码验证界面
        root = tk.Tk()
        app = PasswordVerificationApp(root)
        root.mainloop()


if __name__ == "__main__":
    main()