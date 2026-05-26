import os
import re
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

# ======================= 规则库 =======================
# PHP 危险函数
PHP_DANGER_FUNC = [
    "eval", "exec", "system", "passthru", "shell_exec",
    "popen", "proc_open", "assert", "include", "require",
    "include_once", "require_once", "file_get_contents",
    "fopen", "readfile", "unlink", "mkdir", "move_uploaded_file"
]

# PHP 漏洞正则
PHP_RULES = {
    "SQL注入": r"(mysqli_query|mysql_query|query|select.*\$|insert.*\$|update.*\$)",
    "XSS漏洞": r"(echo.*\$|print.*\$|var_dump.*\$)",
    "命令执行": r"(exec|system|passthru|shell_exec)\(",
    "文件包含": r"(include|require|include_once|require_once)\(",
    "文件上传": r"move_uploaded_file\(",
    "硬编码密码": r"password.*=.*['\"].*['\"]|pass.*=.*['\"].*['\"]",
}

# Java 危险类/方法
JAVA_DANGER_CLASS = [
    "Runtime.getRuntime()", "ProcessBuilder",
    "FileOutputStream", "FileInputStream",
    "ObjectInputStream", "SQLException",
    "Statement", "PreparedStatement",
]

# Java 漏洞正则
JAVA_RULES = {
    "SQL注入": r"Statement|executeQuery|executeUpdate.*\+",
    "命令执行": r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder",
    "反序列化风险": r"ObjectInputStream",
    "文件操作风险": r"File\(|FileInputStream|FileOutputStream",
    "硬编码密码": r"password.*=.*\"|pass.*=.*\"",
    "XSS输出": r"response\.getWriter|print|println",
}

# ======================================================

class CodeAuditTool:
    def __init__(self, root):
        self.root = root
        self.root.title("代码审计工具 - PHP / Java 漏洞扫描")
        self.root.geometry("950x650")
        # 主窗口底色：浅蓝
        self.root.configure(bg="#f0f7ff")
        self.root.resizable(False, False)

        # 标题
        tk.Label(root, text="代码审计工具 | 支持 PHP / Java",
                 font=("微软雅黑", 14, "bold"),
                 bg="#f0f7ff", fg="#1a52b8").pack(pady=10)

        # 选择目录区域
        f = tk.Frame(root, bg="#e6f0ff", padx=15, pady=10)
        f.pack(fill="x", padx=20)
        tk.Label(f, text="项目路径：", bg="#e6f0ff", fg="#0f3c80", font=("微软雅黑", 11)).grid(row=0, column=0)
        self.path_entry = tk.Entry(f, width=50, font=("微软雅黑", 11), bg="white", fg="#222222")
        self.path_entry.grid(row=0, column=1, padx=10)
        tk.Button(f, text="浏览", command=self.select_dir, bg="#4080ff", fg="white", relief="flat").grid(row=0, column=2)

        # 功能按钮区域
        bf = tk.Frame(root, bg="#f0f7ff", pady=10)
        bf.pack()
        tk.Button(bf, text="扫描 PHP 代码", command=self.audit_php,
                  bg="#5b9df9", fg="white", width=16, height=2, relief="flat").grid(row=0, column=0, padx=5)
        tk.Button(bf, text="扫描 Java 代码", command=self.audit_java,
                  bg="#367bf0", fg="white", width=16, height=2, relief="flat").grid(row=0, column=1, padx=5)
        tk.Button(bf, text="一键全扫描", command=self.full_audit,
                  bg="#1a66ff", fg="white", width=16, height=2, relief="flat").grid(row=0, column=2, padx=5)
        tk.Button(bf, text="清空日志", command=self.clear_log,
                  bg="#86a8e7", fg="white", width=16, height=2, relief="flat").grid(row=0, column=3, padx=5)

        # 日志输出区域：白底黑字
        self.log = scrolledtext.ScrolledText(root, bg="white", fg="#222222", font=("Consolas", 10))
        self.log.pack(fill="both", expand=True, padx=20, pady=10)

    def log_print(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def clear_log(self):
        self.log.delete(1.0, tk.END)

    def select_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, dir_path)

    def get_dir(self):
        return self.path_entry.get().strip()

    # 扫描单个文件
    def scan_file(self, filepath, language):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except:
            return

        self.log_print(f"[*] 扫描文件：{filepath}")
        vuln_count = 0

        if language == "php":
            rules = PHP_RULES
            danger = PHP_DANGER_FUNC
        else:
            rules = JAVA_RULES
            danger = JAVA_DANGER_CLASS

        # 正则匹配漏洞
        for vuln_name, pattern in rules.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for m in matches:
                self.log_print(f"[!] 发现 {vuln_name} -> {m}")
                vuln_count += 1

        # 匹配危险函数/类
        for func in danger:
            if func in content:
                self.log_print(f"[!] 危险函数：{func}")
                vuln_count += 1

        if vuln_count == 0:
            self.log_print("[+] 未发现漏洞\n")
        else:
            self.log_print(f"[+] 该文件共发现 {vuln_count} 个风险点\n")

    # 遍历目录执行扫描
    def run_scan(self, ext, language):
        root_dir = self.get_dir()
        if not root_dir or not os.path.isdir(root_dir):
            self.log_print("[!] 请选择有效目录")
            return

        self.log_print("=" * 60)
        self.log_print(f"开始 {language.upper()} 代码审计...")
        self.log_print("=" * 60)

        count = 0
        for path, _, files in os.walk(root_dir):
            for file in files:
                if file.endswith(ext):
                    full = os.path.join(path, file)
                    self.scan_file(full, language)
                    count += 1

        self.log_print(f"[√] 扫描完成，共扫描 {count} 个文件")

    def audit_php(self):
        self.run_scan(".php", "php")

    def audit_java(self):
        self.run_scan(".java", "java")

    def full_audit(self):
        self.clear_log()
        self.audit_php()
        self.audit_java()

if __name__ == "__main__":
    root = tk.Tk()
    CodeAuditTool(root)
    root.mainloop()