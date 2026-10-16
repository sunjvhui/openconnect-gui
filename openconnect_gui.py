#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenConnect GUI — 轻量级 OpenConnect VPN 图形客户端
支持协议: Cisco AnyConnect / GlobalProtect / Pulse / F5 / Fortinet / Array / Juniper

依赖:
  - openconnect   (brew install openconnect)
  - Python 3 (macOS 自带, 含 tkinter)
  - sudo 权限 (推荐为 openconnect 配置免密 sudoers)

用法:
  ./openconnect_gui.py
"""

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from dataclasses import dataclass, asdict
from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

APP_NAME = "OpenConnect GUI"
APP_VERSION = "1.0.0"

CONFIG_DIR = Path.home() / ".openconnect-gui"
PROFILES_FILE = CONFIG_DIR / "profiles.json"
DEBUG_LOG = CONFIG_DIR / "debug.log"


def debug_log(msg):
    """追加调试日志到 ~/.openconnect-gui/debug.log（用于诊断界面回调异常）"""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass

OPENCONNECT = shutil.which("openconnect") or "/opt/homebrew/bin/openconnect"

PROTOCOLS = ["anyconnect", "gp", "pulse", "f5", "fortinet", "nc", "array"]
PROTOCOL_LABELS = {
    "anyconnect": "Cisco AnyConnect",
    "gp": "GlobalProtect",
    "pulse": "Pulse Connect Secure",
    "f5": "F5 Big-IP",
    "fortinet": "Fortinet",
    "nc": "Juniper (Network Connect)",
    "array": "Array AG",
}

# ---- 状态 ----
ST_DISCONNECTED = "disconnected"
ST_CONNECTING = "connecting"
ST_CONNECTED = "connected"

# ---- 输出识别 ----
RE_PROMPT_TAIL = re.compile(r"[:：]\s*$")
RE_PASSWORD_PROMPT = re.compile(
    r"(second\s*password|password|passcode|pass\s*phrase|otp|one[-\s]?time|"
    r"token\s*code|verification\s*code|mfa|2fa|code)", re.I)
RE_SUDO_PROMPT = re.compile(r"(\[sudo\]\s*password|password\s+for\s+.+:)", re.I)
RE_PROMPT_KEYWORD = re.compile(
    r"(password|passcode|pass\s*phrase|otp|one[-\s]?time|second|factor|token|"
    r"verification|verify|mfa|2fa|dynamic|\u5b89\u5168\u7801|\u52a8\u6001|\u9a8c\u8bc1\u7801|\u5bc6\u7801|"
    r"username|user\s*name|gateway|group|select|choose|choice|accept|"
    r"continue|confirm|yes/no|y/n|\[[0-9a-z/]+\])", re.I)
RE_CONNECTED = re.compile(r"(Connected\s+(as|to)\b|DTLS\s+connected)", re.I)
RE_ERROR = re.compile(r"(error|failed|failure|denied|refused|incorrect)", re.I)
RE_SERVERCERT = re.compile(r"pin-sha256:[A-Za-z0-9+/=]{20,}")
RE_WARN = re.compile(r"(warn|warning)", re.I)


# ============================================================
# 配置数据
# ============================================================
@dataclass
class Profile:
    name: str = ""
    host: str = ""
    port: str = "443"
    protocol: str = "anyconnect"
    usergroup: str = ""
    username: str = ""
    remember_password: bool = False
    no_dtls: bool = False
    proxy: str = ""
    cafile: str = ""
    servercert: str = ""


def load_profiles():
    try:
        data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        profiles = [Profile(**{k: p.get(k, "") for k in Profile().__dict__}) for p in data.get("profiles", [])]
        return profiles, data.get("last", "")
    except Exception:
        return [], ""


def save_profiles(profiles, last=""):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {"version": 1, "last": last, "profiles": [asdict(p) for p in profiles]}
    PROFILES_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ============================================================
# macOS 钥匙串 (其他平台返回不可用)
# ============================================================
def keychain_available():
    return sys.platform == "darwin" and shutil.which("security") is not None


def keychain_service(profile_name):
    return f"openconnect-gui/{profile_name}"


def keychain_set(profile_name, account, secret):
    if not keychain_available():
        return False
    try:
        subprocess.run(
            ["security", "add-generic-password", "-U",
             "-a", account or "-", "-s", keychain_service(profile_name), "-w", secret],
            check=True, capture_output=True, timeout=10)
        return True
    except Exception:
        return False


def keychain_get(profile_name, account):
    if not keychain_available():
        return None
    try:
        r = subprocess.run(
            ["security", "find-generic-password",
             "-a", account or "-", "-s", keychain_service(profile_name), "-w"],
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip() or None
    except Exception:
        pass
    return None


def keychain_delete(profile_name, account):
    if not keychain_available():
        return
    try:
        subprocess.run(
            ["security", "delete-generic-password",
             "-a", account or "-", "-s", keychain_service(profile_name)],
            capture_output=True, timeout=10)
    except Exception:
        pass


# ============================================================
# sudo 校验
# ============================================================
def ensure_askpass():
    """创建 macOS 原生提权辅助脚本（sudo -A 用），返回路径；非 macOS 返回 None"""
    if sys.platform != "darwin":
        return None
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = CONFIG_DIR / "askpass.sh"
    script = (
        "#!/bin/sh\n"
        "exec /usr/bin/osascript -e "
        "'display dialog \"OpenConnect GUI 需要 root 权限运行 openconnect，请输入管理员密码：\" "
        "default answer \"\" with hidden answer' "
        "-e 'text returned of result' 2>/dev/null\n"
    )
    path.write_text(script, encoding="utf-8")
    path.chmod(0o700)
    return path


# ============================================================
# VPN 连接进程封装
# ============================================================
class VPNConnection:
    """在后台线程运行 openconnect, 通过队列向 UI 推送事件"""

    def __init__(self, event_queue):
        self.q = event_queue
        self.proc = None
        self.stopping = False

    @property
    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, argv, first_input=None, env=None):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,              # 行缓冲
            start_new_session=True, # 独立进程组, 断开时可整组清理
            env=env,
        )
        if first_input is not None:
            self.send(first_input)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        p = self.proc
        try:
            for raw in iter(p.stdout.readline, ""):
                line = raw.rstrip("\r\n")
                if line.strip():
                    self.q.put(("log", line))
        except Exception:
            pass
        try:
            code = p.wait()
        except Exception:
            code = -1
        self.q.put(("ended", code))

    def send(self, text):
        try:
            self.proc.stdin.write(text + "\n")
            self.proc.stdin.flush()
            return True
        except Exception:
            return False

    def stop(self):
        if not self.alive:
            return
        self.stopping = True
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except Exception:
            try:
                self.proc.terminate()
            except Exception:
                pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


# ============================================================
# 输入对话框 (用于 OTP / 二次密码 / sudo 密码等)
# ============================================================
class PromptDialog(tk.Toplevel):
    def __init__(self, master, title, message, masked=True, initial="", allow_suppress=False):
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.configure(padx=16, pady=14)
        self.result = None

        ttk.Label(self, text=message, wraplength=380).pack(anchor="w", pady=(0, 10))

        self.var = tk.StringVar(value=initial)
        ent = ttk.Entry(self, textvariable=self.var, width=42,
                        show="•" if masked else "")
        ent.pack(fill="x", pady=(0, 14))
        ent.focus_set()

        self.suppress = False
        if allow_suppress:
            self.var_sup = tk.BooleanVar(value=False)
            ttk.Checkbutton(self, text="本次连接内不再自动弹出（可改用「手动输入…」）",
                            variable=self.var_sup).pack(anchor="w", pady=(0, 10))

        btns = ttk.Frame(self)
        btns.pack(fill="x")
        ttk.Button(btns, text="取消", command=self._cancel).pack(side="right", padx=(8, 0))
        ttk.Button(btns, text="确定", command=self._ok).pack(side="right")
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.transient(master)
        self.grab_set()

    def _ok(self):
        if not self.var.get().strip():
            return          # 空输入不发送, 防止误触导致服务器重复提问
        self.result = self.var.get()
        if hasattr(self, "var_sup"):
            self.suppress = bool(self.var_sup.get())
        self.grab_release()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.grab_release()
        self.destroy()


# ============================================================
# 主应用
# ============================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1020x720")
        self.minsize(900, 620)

        self.state = ST_DISCONNECTED
        self.connected_at = None
        self.conn = None
        self.q = queue.Queue()
        self._prompt_open = False
        self._pending_prompts = []      # [(title, message, masked)]
        self._prompt_candidate = None
        self._prompt_candidate_timer = None
        self._last_line_time = time.time()
        self._suppress_prompts = False
        self._pending_servercert = None
        self._pw_prompts_seen = 0
        self._sudo_ok_nopass = False

        self._setup_style()
        self._build_menu()
        self._build_ui()
        self._load()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll)
        self.after(1000, self._tick_clock)
        if "--autotest" in sys.argv:
            self.after(1500, self._run_autotest)

    def report_callback_exception(self, exc, val, tb):
        text = "".join(traceback.format_exception(exc, val, tb))
        debug_log("Tk 回调异常:\n" + text)
        try:
            self.log_line("⚠ 界面异常: " + text.strip(), "err")
        except Exception:
            pass

    # ---------------- 自测: 模拟点击「连接」 ----------------
    def _run_autotest(self):
        debug_log("AUTOTEST: 开始模拟点击「连接」")
        dummy = CONFIG_DIR / "askpass-dummy.sh"
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        dummy.write_text("#!/bin/sh\necho wrong-password\n", encoding="utf-8")
        dummy.chmod(0o700)
        self._get_askpass = lambda: dummy
        self.var_host.set("127.0.0.1")
        self.var_port.set("1")
        self.var_user.set("autotest")
        self.var_pw.set("autotest-pass")
        try:
            self._do_connect()
            debug_log("AUTOTEST: _do_connect 正常返回")
        except Exception:
            debug_log("AUTOTEST: _do_connect 异常:\n" + traceback.format_exc())
        self.after(9000, self._autotest_finish)

    def _autotest_finish(self):
        alive = bool(self.conn and self.conn.alive)
        debug_log(f"AUTOTEST 结束: state={self.state} alive={alive}")
        self.destroy()

    # ---------------- 样式 ----------------
    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("aqua")
        except Exception:
            pass
        style.configure("TLabelframe.Label", font=("PingFang SC", 12, "bold"))
        style.configure("Status.TLabel", font=("PingFang SC", 11))
        style.configure("Big.TButton", font=("PingFang SC", 12, "bold"), padding=(18, 6))

    # ---------------- 菜单 ----------------
    def _build_menu(self):
        menubar = tk.Menu(self)

        m_app = tk.Menu(menubar, tearoff=0)
        m_app.add_command(label="关于 " + APP_NAME, command=self._show_about)
        m_app.add_separator()
        m_app.add_command(label="退出", accelerator="Cmd+Q", command=self._on_close)
        menubar.add_cascade(label="OpenConnect", menu=m_app)

        m_conn = tk.Menu(menubar, tearoff=0)
        m_conn.add_command(label="连接", accelerator="Cmd+K", command=self._on_connect)
        m_conn.add_command(label="断开", accelerator="Cmd+D", command=self._on_disconnect)
        menubar.add_cascade(label="连接", menu=m_conn)

        m_prof = tk.Menu(menubar, tearoff=0)
        m_prof.add_command(label="保存当前配置", accelerator="Cmd+S", command=self._save_current_profile)
        m_prof.add_command(label="删除所选配置", command=self._delete_selected_profile)
        m_prof.add_separator()
        m_prof.add_command(label="打开配置文件夹", command=self._open_config_dir)
        menubar.add_cascade(label="配置", menu=m_prof)

        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="Sudo 免密配置说明…", command=self._show_sudo_help)
        m_help.add_command(label="使用说明…", command=self._show_usage)
        menubar.add_cascade(label="帮助", menu=m_help)

        self.config(menu=menubar)

        self.bind("<Command-k>", lambda e: self._on_connect())
        self.bind("<Command-d>", lambda e: self._on_disconnect())
        self.bind("<Command-s>", lambda e: self._save_current_profile())
        self.bind("<Command-q>", lambda e: self._on_close())

    # ---------------- 界面 ----------------
    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.pack(fill="both", expand=True)

        # ============ 上半部分: 左配置列表 + 右表单 ============
        top = ttk.Frame(main)
        top.pack(fill="x")

        # --- 左侧: 配置列表 ---
        left = ttk.Labelframe(top, text=" 配置 ", padding=10)
        left.pack(side="left", fill="y", padx=(0, 12))

        self.lst = tk.Listbox(left, width=26, height=9, exportselection=False,
                              activestyle="dotbox",
                              font=("PingFang SC", 11))
        self.lst.pack(fill="both", expand=True)
        self.lst.bind("<<ListboxSelect>>", lambda e: self._on_select_profile())

        lbtns = ttk.Frame(left)
        lbtns.pack(fill="x", pady=(8, 0))
        ttk.Button(lbtns, text="＋ 新建", width=8, command=self._new_profile).pack(side="left", expand=True, fill="x")
        ttk.Button(lbtns, text="🗑 删除", width=8, command=self._delete_selected_profile).pack(side="left", padx=(6, 0), expand=True, fill="x")
        ttk.Button(left, text="💾 保存配置", command=self._save_current_profile).pack(fill="x", pady=(6, 0))

        # --- 右侧: 连接表单 ---
        right = ttk.Frame(top)
        right.pack(side="left", fill="both", expand=True)

        # openconnect 检测提示
        if shutil.which(OPENCONNECT) is None:
            ttk.Label(right, foreground="#c62828",
                      text="⚠ 未找到 openconnect，请先安装: brew install openconnect").pack(anchor="w", pady=(0, 6))

        form = ttk.Frame(right)
        form.pack(fill="x")

        # 服务器
        ttk.Label(form, text="服务器").grid(row=0, column=0, sticky="w", pady=5, padx=(0, 8))
        self.var_host = tk.StringVar()
        host_ent = ttk.Entry(form, textvariable=self.var_host, width=34)
        host_ent.grid(row=0, column=1, sticky="w", pady=5)
        ttk.Label(form, text="端口").grid(row=0, column=2, sticky="e", pady=5, padx=(14, 6))
        self.var_port = tk.StringVar(value="443")
        ttk.Combobox(form, textvariable=self.var_port, width=7, values=("443", "8443")).grid(row=0, column=3, sticky="w")

        # 协议 + 用户组
        ttk.Label(form, text="协议").grid(row=1, column=0, sticky="w", pady=5, padx=(0, 8))
        self.var_protocol = tk.StringVar(value="anyconnect")
        proto_cb = ttk.Combobox(form, textvariable=self.var_protocol, width=18, state="readonly",
                                values=[f"{k} · {v}" for k, v in PROTOCOL_LABELS.items()])
        proto_cb.grid(row=1, column=1, sticky="w")
        proto_cb.bind("<<ComboboxSelected>>", lambda e: self.var_protocol.set(self.var_protocol.get().split(" · ")[0]))
        ttk.Label(form, text="用户组").grid(row=1, column=2, sticky="e", pady=5, padx=(14, 6))
        self.var_group = tk.StringVar()
        ttk.Entry(form, textvariable=self.var_group, width=12).grid(row=1, column=3, sticky="w")

        # 用户名
        ttk.Label(form, text="用户名").grid(row=2, column=0, sticky="w", pady=5, padx=(0, 8))
        self.var_user = tk.StringVar()
        ttk.Entry(form, textvariable=self.var_user, width=34).grid(row=2, column=1, sticky="w")

        # 密码
        ttk.Label(form, text="密码").grid(row=3, column=0, sticky="w", pady=5, padx=(0, 8))
        self.var_pw = tk.StringVar()
        self.pw_ent = ttk.Entry(form, textvariable=self.var_pw, width=34, show="•")
        self.pw_ent.grid(row=3, column=1, sticky="w")
        self.var_remember = tk.BooleanVar(value=False)
        self.chk_remember = ttk.Checkbutton(
            form, text="记住密码" + ("（钥匙串）" if keychain_available() else "（不安全）"),
            variable=self.var_remember)
        self.chk_remember.grid(row=3, column=2, columnspan=2, sticky="w", padx=(14, 0))

        # 高级选项 (可折叠)
        self.var_advanced = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="高级选项", variable=self.var_advanced,
                        command=self._toggle_advanced).grid(row=4, column=0, columnspan=4, sticky="w", pady=(6, 0))

        self.adv = ttk.Frame(form)
        # 高级: 代理 / CA
        ttk.Label(self.adv, text="代理").grid(row=0, column=0, sticky="w", pady=5, padx=(0, 8))
        ttk.Label(self.adv, text="(如 http://host:80 或 socks5://host:1080)",
                  foreground="#777").grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.var_proxy = tk.StringVar()
        ttk.Entry(self.adv, textvariable=self.var_proxy, width=28).grid(row=0, column=1, sticky="w")
        ttk.Label(self.adv, text="CA 证书").grid(row=1, column=0, sticky="w", pady=5, padx=(0, 8))
        self.var_ca = tk.StringVar()
        ttk.Entry(self.adv, textvariable=self.var_ca, width=28).grid(row=1, column=1, sticky="w")
        ttk.Button(self.adv, text="浏览…", width=6, command=self._browse_ca).grid(row=1, column=2, sticky="w", padx=(8, 0))
        self.var_nodtls = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.adv, text="禁用 DTLS（提高兼容性）", variable=self.var_nodtls).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Label(self.adv, text="证书指纹").grid(row=3, column=0, sticky="w", pady=5, padx=(0, 8))
        self.var_servercert = tk.StringVar()
        ttk.Entry(self.adv, textvariable=self.var_servercert, width=34).grid(row=3, column=1, sticky="w")
        ttk.Label(self.adv, text="pin-sha256:…（首次连接失败时自动捕获）",
                  foreground="#777").grid(row=3, column=2, sticky="w", padx=(8, 0))

        # 连接按钮
        btnrow = ttk.Frame(right)
        btnrow.pack(fill="x", pady=(14, 10))
        self.btn_connect = ttk.Button(btnrow, text="🔗 连 接", style="Big.TButton", command=self._on_connect)
        self.btn_connect.pack(side="left")
        self.btn_disconnect = ttk.Button(btnrow, text="⏹ 断 开", style="Big.TButton",
                                         command=self._on_disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(10, 0))

        # ============ 状态栏 ============
        status = ttk.Frame(main)
        status.pack(fill="x", pady=(2, 8))
        self.var_status = tk.StringVar(value="● 未连接")
        self.lbl_status = ttk.Label(status, textvariable=self.var_status, style="Status.TLabel")
        self.lbl_status.pack(side="left")
        self.var_duration = tk.StringVar(value="")
        ttk.Label(status, textvariable=self.var_duration, style="Status.TLabel", foreground="#666").pack(side="left", padx=(12, 0))

        # ============ 日志 ============
        logf = ttk.Labelframe(main, text=" 日志 ", padding=6)
        logf.pack(fill="both", expand=True)

        self.log = ScrolledText(logf, wrap="word", state="disabled",
                                font=("Menlo", 11), bg="#1e1e1e", fg="#d4d4d4",
                                insertbackground="#d4d4d4", relief="flat",
                                padx=10, pady=8, height=12)
        self.log.pack(side="left", fill="both", expand=True)
        for tag, color in (("err", "#f48771"), ("warn", "#cca700"),
                           ("ok", "#89d185"), ("dim", "#808080")):
            self.log.tag_configure(tag, foreground=color)

        logbtns = ttk.Frame(logf)
        logbtns.pack(side="right", fill="y", padx=(8, 0))
        ttk.Button(logbtns, text="手动输入…", command=self._manual_input).pack(fill="x")
        ttk.Button(logbtns, text="清空日志", command=self._clear_log).pack(fill="x", pady=(6, 0))

    def _toggle_advanced(self):
        if self.var_advanced.get():
            self.adv.grid(row=5, column=0, columnspan=4, sticky="w", pady=(4, 0))
        else:
            self.adv.grid_forget()

    def _browse_ca(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="选择 CA 证书",
                                          filetypes=[("证书", "*.pem *.crt *.cer *.p12"), ("所有文件", "*.*")])
        if path:
            self.var_ca.set(path)

    # ---------------- 日志 ----------------
    def log_line(self, line, kind=None):
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n", kind or "")
        # 限制行数
        if int(self.log.index("end-1c").split(".")[0]) > 5000:
            self.log.delete("1.0", "200.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ---------------- 事件轮询 ----------------
    def _poll(self):
        try:
            while True:
                try:
                    kind, val = self.q.get_nowait()
                except queue.Empty:
                    break
                if kind == "log":
                    self._on_line(val)
                elif kind == "ended":
                    self._on_ended(val)
            # 弹出排队的提示
            if not self._prompt_open and self._pending_prompts:
                title, msg, masked = self._pending_prompts.pop(0)
                self._show_prompt(title, msg, masked)
        except Exception:
            debug_log("_poll 异常:\n" + traceback.format_exc())
        self.after(100, self._poll)

    def _on_line(self, line):
        self._last_line_time = time.time()
        if RE_ERROR.search(line):
            kind = "err"
        elif RE_WARN.search(line):
            kind = "warn"
        elif RE_CONNECTED.search(line):
            kind = "ok"
            if self.state != ST_CONNECTED:
                self._set_state(ST_CONNECTED)
        else:
            kind = None
        self.log_line(line, kind)

        # 服务器证书验证失败时 openconnect 会给出 pin-sha256 指纹, 自动捕获
        m = RE_SERVERCERT.search(line)
        if m and m.group(0) != self.var_servercert.get().strip():
            self._pending_servercert = m.group(0)
            self.log_line(f"➜ 已捕获服务器证书指纹: {m.group(0)}", "warn")
            # openconnect 验证失败后可能挂起等待交互而非退出, 不等 ended 事件
            self.after(600, lambda pin=m.group(0): self._cert_failure_flow(pin))

        # sudo 密码提示
        if RE_SUDO_PROMPT.search(line):
            self._queue_prompt("需要 sudo 密码", line.strip(), masked=True, sudo=True)
            return

        # 交互提示: 行尾冒号 + 关键词 → 先记为候选, 静默 1.8s 后才真正弹框
        if (self.state != ST_DISCONNECTED and self.conn and self.conn.alive
                and not self._suppress_prompts
                and RE_PROMPT_TAIL.search(line)
                and len(line) < 120
                and RE_PROMPT_KEYWORD.search(line)):
            if RE_PASSWORD_PROMPT.search(line):
                self._pw_prompts_seen += 1
                if self._pw_prompts_seen == 1:
                    return  # 首个密码提示已随连接自动发送
            self._arm_prompt_candidate(line.strip())

    def _queue_prompt(self, title, msg, masked, sudo=False):
        self._pending_prompts.append((("sudo 密码" if sudo else title), msg, masked))

    def _arm_prompt_candidate(self, line):
        """记录提示候选行; 若后续 1.8s 内无新输出则判定 openconnect 阻塞等待输入"""
        debug_log(f"提示候选: {line!r}")
        if self._prompt_candidate_timer:
            try:
                self.after_cancel(self._prompt_candidate_timer)
            except Exception:
                pass
        self._prompt_candidate = line
        self._prompt_candidate_timer = self.after(1800, self._fire_prompt_candidate)

    def _fire_prompt_candidate(self):
        self._prompt_candidate_timer = None
        line, self._prompt_candidate = self._prompt_candidate, None
        if not line or self._prompt_open or self._suppress_prompts:
            return
        if not (self.conn and self.conn.alive):
            return
        # 静默期内又有新输出 → 是流式日志而非阻塞提示, 放弃
        if time.time() - self._last_line_time < 1.6:
            return
        masked = bool(RE_PASSWORD_PROMPT.search(line))
        debug_log(f"静默确认通过, 弹出输入框: {line!r} masked={masked}")
        self._queue_prompt("请输入", line, masked)

    def _show_prompt(self, title, msg, masked):
        self._prompt_open = True
        dlg = PromptDialog(self, title, msg, masked=masked, allow_suppress=True)
        self.wait_window(dlg)
        self._prompt_open = False
        if getattr(dlg, "suppress", False):
            self._suppress_prompts = True
            self.log_line("➜ 已停用自动弹窗; 需要时请点「手动输入…」", "dim")
        if dlg.result is not None and self.conn:
            self.log_line(f"➜ 已发送输入 ({'*' * len(dlg.result) if masked else dlg.result})", "dim")
            self.conn.send(dlg.result)

    def _manual_input(self):
        if not (self.conn and self.conn.alive):
            messagebox.showinfo(APP_NAME, "当前没有活动连接。", parent=self)
            return
        dlg = PromptDialog(self, "手动输入", "向 openconnect 进程发送一行输入（用于 2FA、组选择等）:", masked=False)
        if dlg.result:
            self.conn.send(dlg.result)
            self.log_line("➜ " + dlg.result, "dim")

    # ---------------- 状态 ----------------
    def _set_state(self, state):
        self.state = state
        colors = {ST_DISCONNECTED: "#9e9e9e", ST_CONNECTING: "#f57f17", ST_CONNECTED: "#2e7d32"}
        texts = {ST_DISCONNECTED: "● 未连接", ST_CONNECTING: "◉ 连接中…", ST_CONNECTED: "● 已连接"}
        self.lbl_status.configure(foreground=colors[state])
        self.var_status.set(texts[state])

        if state == ST_CONNECTED:
            self.connected_at = self.connected_at or time.time()
            self.btn_connect.configure(state="disabled")
            self.btn_disconnect.configure(state="normal")
        elif state == ST_CONNECTING:
            self.btn_connect.configure(state="disabled")
            self.btn_disconnect.configure(state="normal")
        else:
            self.connected_at = None
            self.var_duration.set("")
            self.btn_connect.configure(state="normal")
            self.btn_disconnect.configure(state="disabled")

    def _tick_clock(self):
        if self.state == ST_CONNECTED and self.connected_at:
            d = int(time.time() - self.connected_at)
            h, rem = divmod(d, 3600)
            m, s = divmod(rem, 60)
            self.var_duration.set(f"已连接 {h:02d}:{m:02d}:{s:02d}" if h else f"已连接 {m:02d}:{s:02d}")
        self.after(1000, self._tick_clock)

    # ---------------- 连接 ----------------
    def _on_connect(self, event=None):
        debug_log("用户点击「连接」")
        try:
            self._do_connect()
        except Exception:
            text = traceback.format_exc()
            debug_log("连接异常:\n" + text)
            try:
                self.log_line("⚠ 连接异常: " + text.strip(), "err")
                messagebox.showerror(APP_NAME, "连接时发生错误:\n" + text[-800:], parent=self)
            except Exception:
                pass

    def _do_connect(self):
        debug_log(f"表单读取: state={self.state}")
        if self.state != ST_DISCONNECTED:
            if messagebox.askyesno(APP_NAME, "当前已有连接，是否断开后重新连接？", parent=self):
                self._on_disconnect()
            return

        host = self.var_host.get().strip()
        user = self.var_user.get().strip()
        protocol = self.var_protocol.get().split(" · ")[0]
        if not host:
            messagebox.showwarning(APP_NAME, "请填写服务器地址。", parent=self)
            return
        if not user:
            messagebox.showwarning(APP_NAME, "请填写用户名。", parent=self)
            return
        debug_log(f"表单: host={host!r} port={self.var_port.get()!r} user={user!r} proto={protocol!r}")

        # 获取密码: 输入框 → 钥匙串
        pw = self.var_pw.get()
        if not pw:
            name = self._current_profile_name()
            if name and self.var_remember.get():
                pw = keychain_get(name, user) or ""
                if pw:
                    self.log_line("➜ 已从钥匙串读取密码", "dim")
        if not pw:
            messagebox.showwarning(APP_NAME, "请填写密码。", parent=self)
            self.pw_ent.focus_set()
            return

        if not shutil.which(OPENCONNECT):
            messagebox.showerror(APP_NAME, "未找到 openconnect，请先安装:\n  brew install openconnect", parent=self)
            return
        debug_log(f"openconnect 路径 OK: {OPENCONNECT}, euid={os.geteuid()}")

        # sudo 权限: macOS 用原生 askpass 弹窗(sudo -A)，凭票据缓存自动跳过
        spawn_env = None
        port = self.var_port.get().strip()
        server = host if (":" in host or not port) else f"{host}:{port}"
        cmd = []
        if os.geteuid() != 0:
            if not shutil.which("sudo"):
                messagebox.showerror(APP_NAME, "未找到 sudo。", parent=self)
                return
            askpass = self._get_askpass()
            if askpass:
                cmd += ["sudo", "-A"]
                spawn_env = dict(os.environ, SUDO_ASKPASS=str(askpass))
                debug_log(f"使用 sudo -A + askpass: {askpass}")
            else:
                cmd += ["sudo", "-n"]
        cmd += [OPENCONNECT,
                "--protocol", protocol,
                "--server", server,
                "--user", user,
                "--passwd-on-stdin"]
        if self.var_group.get().strip():
            cmd += ["--usergroup", self.var_group.get().strip()]
        if self.var_proxy.get().strip():
            cmd += ["--proxy", self.var_proxy.get().strip()]
        if self.var_ca.get().strip():
            cmd += ["--cafile", self.var_ca.get().strip()]
        if self.var_servercert.get().strip():
            cmd += ["--servercert", self.var_servercert.get().strip()]
        if self.var_nodtls.get():
            cmd.append("--no-dtls")

        debug_log("spawn: " + " ".join(cmd))
        self._pw_prompts_seen = 0
        self._pending_prompts.clear()
        self._suppress_prompts = False
        self._pending_servercert = None
        self.conn = VPNConnection(self.q)
        self.log_line(f"$ {' '.join(cmd)}", "dim")
        self.log_line(f"➜ 正在连接 {server} ({PROTOCOL_LABELS.get(protocol, protocol)})…", "dim")
        try:
            self.conn.start(cmd, first_input=pw, env=spawn_env)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"启动 openconnect 失败:\n{e}", parent=self)
            self._set_state(ST_DISCONNECTED)
            return
        debug_log(f"进程已启动 pid={self.conn.proc.pid}")
        self._set_state(ST_CONNECTING)

        # 自动保存配置(勾选记住密码时)
        if self.var_remember.get():
            self._save_current_profile(silent=True)

    def _get_askpass(self):
        return ensure_askpass()

    def _on_disconnect(self):
        if self.conn and self.conn.alive:
            self.log_line("➜ 正在断开连接…", "dim")
            self.conn.stop()
        self._set_state(ST_DISCONNECTED)

    def _on_ended(self, code):
        self.log_line(f"➜ openconnect 进程已退出 (code={code})", "dim" if code == 0 else "err")
        if self.state != ST_DISCONNECTED:
            self._set_state(ST_DISCONNECTED)
        pin = self._pending_servercert
        if pin and code != 0:
            self._pending_servercert = None
            self.after(400, lambda: self._offer_server_trust(pin))

    def _cert_failure_flow(self, pin):
        """证书验证失败: 主动结束挂起的失败进程, 立即询问是否信任并重连"""
        if self._pending_servercert != pin:
            return  # 已被 ended 事件或用户处理过
        self._pending_servercert = None
        # 取消可能在等待的提示候选定时器
        if self._prompt_candidate_timer:
            try:
                self.after_cancel(self._prompt_candidate_timer)
            except Exception:
                pass
            self._prompt_candidate_timer = None
        if self.conn and self.conn.alive:
            self.log_line("➜ 结束本次证书验证失败的连接进程…", "dim")
            self.conn.stop()
        self._set_state(ST_DISCONNECTED)
        self._offer_server_trust(pin)

    def _offer_server_trust(self, pin):
        """证书验证失败后一键信任该服务器证书指纹并自动重连"""
        host = self.var_host.get().strip()
        ok = messagebox.askyesno(
            "信任服务器证书",
            f"服务器 {host} 的证书未通过系统验证\n"
            f"(自签名或私有 CA, 公司 VPN 常见)。\n\n"
            f"证书指纹:\n{pin}\n\n"
            f"是否信任该证书并自动重连?\n"
            f"(指纹将保存到配置, 仅对该服务器生效)\n\n"
            f"⚠ 注意: 若该指纹与预期不符, 可能存在中间人风险。",
            parent=self)
        if not ok:
            self.log_line("➜ 已拒绝信任服务器证书, 未保存", "warn")
            return
        self._store_servercert(pin)
        self.log_line("➜ 已信任服务器证书, 正在自动重连…", "ok")
        self.after(300, self._do_connect)

    def _store_servercert(self, value):
        """保存证书指纹到当前配置(不触碰钥匙串)"""
        self.var_servercert.set(value)
        name = self._current_profile_name()
        for prof in self.profiles:
            if prof.name == name:
                prof.servercert = value
                break
        else:
            p = self._form_to_profile(name)
            p.servercert = value
            self.profiles.append(p)
        save_profiles(self.profiles, last=name)

    # ---------------- 配置管理 ----------------
    def _current_profile_name(self):
        sel = self.lst.curselection()
        if sel:
            return self.lst.get(sel[0])
        host = self.var_host.get().strip()
        return host.split(":")[0] if host else ""

    def _form_to_profile(self, name):
        return Profile(
            name=name,
            host=self.var_host.get().strip(),
            port=self.var_port.get().strip() or "443",
            protocol=self.var_protocol.get().split(" · ")[0],
            usergroup=self.var_group.get().strip(),
            username=self.var_user.get().strip(),
            remember_password=self.var_remember.get(),
            no_dtls=self.var_nodtls.get(),
            proxy=self.var_proxy.get().strip(),
            cafile=self.var_ca.get().strip(),
            servercert=self.var_servercert.get().strip(),
        )

    def _profile_to_form(self, p: Profile):
        self.var_host.set(p.host)
        self.var_port.set(p.port or "443")
        self.var_protocol.set(p.protocol or "anyconnect")
        self.var_group.set(p.usergroup or "")
        self.var_user.set(p.username or "")
        self.var_remember.set(bool(p.remember_password))
        self.var_nodtls.set(bool(p.no_dtls))
        self.var_proxy.set(p.proxy or "")
        self.var_ca.set(p.cafile or "")
        self.var_servercert.set(p.servercert or "")
        # 尝试从钥匙串取密码
        self.var_pw.set("")
        if p.remember_password and p.username and keychain_available():
            pw = keychain_get(p.name, p.username)
            if pw:
                self.var_pw.set(pw)

    def _load(self):
        self.profiles, last = load_profiles()
        self.lst.delete(0, "end")
        for p in self.profiles:
            self.lst.insert("end", p.name)
        if self.profiles:
            names = [p.name for p in self.profiles]
            idx = names.index(last) if last in names else 0
            self.lst.selection_set(idx)
            self.lst.activate(idx)
            self.lst.see(idx)
            self._profile_to_form(self.profiles[idx])
        else:
            self._new_profile(silent=True)

    def _new_profile(self, silent=False):
        self.lst.selection_clear(0, "end")
        self.var_host.set("")
        self.var_port.set("443")
        self.var_protocol.set("anyconnect")
        self.var_group.set("")
        self.var_user.set("")
        self.var_pw.set("")
        self.var_remember.set(False)
        self.var_nodtls.set(False)
        self.var_proxy.set("")
        self.var_ca.set("")
        self.var_servercert.set("")
        if not silent:
            self.log_line("➜ 新配置，填写后点击「保存配置」", "dim")
            self.focus_set()

    def _on_select_profile(self):
        sel = self.lst.curselection()
        if not sel:
            return
        p = self.profiles[sel[0]]
        self._profile_to_form(p)
        save_profiles(self.profiles, last=p.name)

    def _save_current_profile(self, silent=False):
        host = self.var_host.get().strip()
        if not host:
            if not silent:
                messagebox.showwarning(APP_NAME, "请先填写服务器地址。", parent=self)
            return
        name = self._current_profile_name() or host.split(":")[0]
        if not silent:
            dlg = PromptDialog(self, "保存配置", "配置名称:", masked=False, initial=name)
            self.wait_window(dlg)
            name = dlg.result
            if not name:
                return
        p = self._form_to_profile(name)

        # 更新或追加
        for i, old in enumerate(self.profiles):
            if old.name == name:
                self.profiles[i] = p
                break
        else:
            self.profiles.append(p)

        # 钥匙串
        if p.remember_password:
            pw = self.var_pw.get()
            if pw and not keychain_set(p.name, p.username, pw) and not silent:
                messagebox.showwarning(APP_NAME, "密码写入钥匙串失败，本次仅保留在内存中。", parent=self)
        else:
            keychain_delete(name, p.username)

        save_profiles(self.profiles, last=name)
        self.lst.delete(0, "end")
        for prof in self.profiles:
            self.lst.insert("end", prof.name)
        idx = [x.name for x in self.profiles].index(name)
        self.lst.selection_set(idx)
        self.lst.see(idx)
        if not silent:
            self.log_line(f"➜ 配置「{name}」已保存", "dim")

    def _delete_selected_profile(self):
        sel = self.lst.curselection()
        if not sel:
            messagebox.showinfo(APP_NAME, "请先在列表中选择一个配置。", parent=self)
            return
        name = self.lst.get(sel[0])
        if not messagebox.askyesno(APP_NAME, f"确定删除配置「{name}」？", parent=self):
            return
        p = self.profiles[sel[0]]
        keychain_delete(p.name, p.username)
        self.profiles.pop(sel[0])
        save_profiles(self.profiles)
        self._load()

    def _open_config_dir(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["open", str(CONFIG_DIR)])

    # ---------------- 帮助 ----------------
    def _show_about(self):
        messagebox.showinfo(
            "关于",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            f"基于 openconnect 的图形化 VPN 客户端。\n"
            f"openconnect: {OPENCONNECT}\n\n"
            f"支持: AnyConnect · GlobalProtect · Pulse · F5 · Fortinet · Array · Juniper",
            parent=self)

    def _show_usage(self):
        win = tk.Toplevel(self)
        win.title("使用说明")
        win.geometry("640x520")
        win.transient(self)
        txt = ScrolledText(win, wrap="word", font=("PingFang SC", 12), padx=14, pady=12)
        txt.pack(fill="both", expand=True)
        txt.insert("end", """使用说明
========

1. 首次使用 sudo 免密配置（推荐）
   在终端执行:
     sudo visudo -f /etc/sudoers.d/openconnect
   写入一行（替换用户名和路径）:
     你的用户名 ALL=(ALL) NOPASSWD: /opt/homebrew/bin/openconnect

   未配置免密时，连接时会弹窗要求输入 Mac 管理员密码。

2. 连接
   • 填写服务器地址、协议、用户名、密码
   • 点击「连接」按钮
   • 如服务器要求 2FA/OTP/组选择，会自动弹窗让你输入

3. 配置管理
   • 填写完成后点击「保存配置」，下次从左侧列表一键加载
   • 勾选「记住密码」后密码存入 macOS 钥匙串

4. 常见协议
   • anyconnect — Cisco AnyConnect (默认)
   • gp — Palo Alto GlobalProtect
   • pulse — Pulse Connect Secure
   • f5 / fortinet / array / nc — 其他厂商

5. 提示
   • 「手动输入…」可在连接过程中向 openconnect 发送任意输入
   • 日志区显示 openconnect 的完整输出，便于排障
   • 断开连接会自动恢复路由和 DNS
""")
        txt.configure(state="disabled")

    def _show_sudo_help(self):
        win = tk.Toplevel(self)
        win.title("Sudo 免密配置")
        win.geometry("620x400")
        win.transient(self)
        frm = ttk.Frame(win, padding=16)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="为 openconnect 配置免密 sudo（只需一次）", font=("PingFang SC", 13, "bold")).pack(anchor="w")
        ttk.Label(frm, text="openconnect 需要 root 权限来修改路由表和 DNS。\n推荐只对 openconnect 一个命令开放免密：", wraplength=560).pack(anchor="w", pady=(8, 10))
        suggestion = f"{os.environ.get('USER', '用户名')} ALL=(ALL) NOPASSWD: {OPENCONNECT}"
        box = tk.Text(frm, height=3, font=("Menlo", 11), bg="#1e1e1e", fg="#d4d4d4", relief="flat", padx=10, pady=8)
        box.insert("end", suggestion)
        box.configure(state="disabled")
        box.pack(fill="x")
        steps = ("操作步骤:\n"
                 "1. 复制上面的一行\n"
                 "2. 终端执行: sudo visudo -f /etc/sudoers.d/openconnect\n"
                 "3. 粘贴并保存\n"
                 "4. 回到本软件重新连接即可")
        ttk.Label(frm, text=steps, justify="left").pack(anchor="w", pady=(12, 10))
        ttk.Button(frm, text="复制到剪贴板", command=lambda: (self.clipboard_clear(), self.clipboard_append(suggestion))).pack()

    # ---------------- 退出 ----------------
    def _on_close(self):
        if self.conn and self.conn.alive:
            if not messagebox.askyesno(APP_NAME, "VPN 当前已连接，退出会断开连接。\n确定退出？", parent=self):
                return
            self.conn.stop()
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
