import requests
import whois
import dns.resolver
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InfoScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("渗透测试信息收集工具 v2.0 | 专业版")
        self.root.geometry("950x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        self.style = ttk.Style()
        self.style.configure(".", bg="#1e1e2e", fg="white")
        self.style.configure("Tab", bg="#2b2b3b", fg="white", padding=10)
        self.style.map("Tab", background=[("selected", "#4f46e5")], foreground=[("selected", "white")])

        title_label = tk.Label(
            root,
            text="信息收集工具 · 存活检测 | WHOIS | DNS | 子域名 | 端口扫描",
            bg="#1e1e2e", fg="#cba6f7", font=("微软雅黑", 13, "bold")
        )
        title_label.pack(pady=10)

        input_frame = tk.Frame(root, bg="#2b2b3b", padx=15, pady=10)
        input_frame.pack(fill="x", padx=20)

        tk.Label(input_frame, text="目标域名：", bg="#2b2b3b", fg="white", font=("微软雅黑", 11)).grid(row=0, column=0)

        self.target_input = tk.Entry(
            input_frame, font=("微软雅黑", 11), width=45,
            bg="#3b3b4d", fg="white", insertbackground="white", bd=0
        )
        self.target_input.grid(row=0, column=1, padx=10)
        self.target_input.insert(0, "baidu.com")

        btn_frame = tk.Frame(root, bg="#1e1e2e", pady=8)
        btn_frame.pack()

        buttons = [
            ("存活检测", self.check_alive, "#89b4fa"),
            ("WHOIS查询", self.whois_scan, "#a6e3a1"),
            ("DNS解析", self.dns_scan, "#f9e2af"),
            ("子域名扫描", self.subdomain_scan, "#fab387"),
            ("端口扫描", self.port_scan, "#f38ba8"),
            ("一键全扫", self.full_scan, "#cba6f7"),
            ("清空所有", self.clear_all, "#6c7086")
        ]

        for idx, (text, func, color) in enumerate(buttons):
            btn = tk.Button(
                btn_frame, text=text, command=func,
                bg=color, fg="black", font=("微软雅黑", 10, "bold"),
                relief="flat", width=11, height=2
            )
            btn.grid(row=0, column=idx, padx=4)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=10)

        self.logs = {}
        self.tab_index = {}
        tabs = ["总览", "存活检测", "WHOIS", "DNS", "子域名", "端口扫描"]
        for idx, tab in enumerate(tabs):
            frame = tk.Frame(self.notebook, bg="#1e1e2e")
            self.notebook.add(frame, text=tab)
            txt = scrolledtext.ScrolledText(
                frame, bg="#181825", fg="white", font=("Consolas", 10),
                relief="flat", insertbackground="white"
            )
            txt.pack(fill="both", expand=True, padx=5, pady=5)
            self.logs[tab] = txt
            self.tab_index[tab] = idx

    def log(self, tab_name, msg):
        txt = self.logs[tab_name]
        txt.insert(tk.END, msg + "\n")
        txt.see(tk.END)
        idx = self.tab_index[tab_name]
        self.notebook.select(idx)

    def clear_all(self):
        for name in self.logs:
            self.logs[name].delete(1.0, tk.END)
        self.log("总览", "[+] 已清空所有日志")

    def get_target(self):
        return self.target_input.get().strip()

    def check_alive(self):
        domain = self.get_target()
        if not domain:
            self.log("存活检测", "[!] 请输入目标")
            return
        self.log("存活检测", f"[*] 正在检测：{domain}")
        urls = [f"http://{domain}", f"https://{domain}"]
        for url in urls:
            try:
                r = requests.get(url, timeout=3, verify=False)
                self.log("存活检测", f"[+] {url} 存活 | 状态码：{r.status_code}")
            except:
                self.log("存活检测", f"[-] {url} 无法访问")

    def whois_scan(self):
        domain = self.get_target()
        self.log("WHOIS", f"[*] 查询WHOIS：{domain}")
        try:
            w = whois.whois(domain)
            self.log("WHOIS", f"[+] 域名：{w.domain_name}")
            self.log("WHOIS", f"[+] 注册商：{w.registrar}")
            self.log("WHOIS", f"[+] 创建时间：{w.creation_date}")
            self.log("WHOIS", f"[+] 过期时间：{w.expiration_date}")
        except:
            self.log("WHOIS", "[-] WHOIS 查询失败")

    def dns_scan(self):
        domain = self.get_target()
        self.log("DNS", f"[*] 解析DNS：{domain}")
        types = ["A", "AAAA", "MX", "CNAME"]
        for t in types:
            try:
                ans = dns.resolver.resolve(domain, t)
                self.log("DNS", f"[+] {t}：{[str(i) for i in ans]}")
            except:
                self.log("DNS", f"[-] {t}：无记录")

    def subdomain_scan(self):
        domain = self.get_target()
        self.log("子域名", f"[*] 扫描子域名：{domain}")
        subs = ["www", "mail", "admin", "api", "test", "cdn", "vpn", "dev", "blog", "ftp"]
        found = 0
        for s in subs:
            d = f"{s}.{domain}"
            try:
                ip = socket.gethostbyname(d)
                self.log("子域名", f"[+] {d} -> {ip}")
                found += 1
            except:
                continue
        if found == 0:
            self.log("子域名", "[-] 未发现子域名")

    # ===================== ✅ 修复后的端口扫描 =====================
    def port_scan(self):
        domain = self.get_target()
        try:
            ip = socket.gethostbyname(domain)
        except:
            self.log("端口扫描", "[-] 域名解析失败")
            return

        self.log("端口扫描", f"[*] 开始扫描 IP：{ip}")
        ports = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8888, 1433]
        open_ports = []

        def scan_single_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    self.log("端口扫描", f"[+] 端口开放：{port}")
                s.close()
            except:
                s.close()
                return

        # EXE 兼容：单线程顺序扫描（最稳定）
        for port in ports:
            scan_single_port(port)

        if not open_ports:
            self.log("端口扫描", "[-] 未发现开放端口")
    # ==============================================================

    def full_scan(self):
        self.clear_all()
        self.log("总览", "====== 开始全量扫描 ======")
        self.check_alive()
        self.whois_scan()
        self.dns_scan()
        self.subdomain_scan()
        self.port_scan()
        self.log("总览", "====== 扫描完成 ======")

if __name__ == "__main__":
    root = tk.Tk()
    app = InfoScannerGUI(root)
    root.mainloop()