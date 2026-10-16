# OpenConnect GUI (macOS)

基于 `openconnect` 的轻量级图形化 VPN 客户端，单文件 Python 实现，无其他依赖。

支持协议：**Cisco AnyConnect · Palo Alto GlobalProtect · Pulse Connect Secure · F5 Big-IP · Fortinet · Array · Juniper**

## 功能

- 🖥 图形界面：服务器 / 协议 / 用户组 / 用户名 / 密码
- 🔐 **2FA / OTP 自动弹窗**：二次密码、验证码、组选择交互式输入
- 📁 多配置管理：保存、一键加载（`~/.openconnect-gui/profiles.json`）
- 🔑 **macOS 钥匙串**存取密码（不落明文）
- 📜 实时日志（终端风格、错误高亮）
- 🛠 sudo 免密探测；未配置时连接前自动请求管理员密码
- ⏱ 连接时长显示、优雅断开（自动恢复路由/DNS）
- 高级选项：代理（HTTP/SOCKS5）、自定义 CA 证书、禁用 DTLS

## 环境要求

```sh
brew install openconnect python@3.13 python-tk@3.13
```

> macOS 自带 Python 的 Tcl/Tk 8.5 已损坏，必须用 Homebrew Python + `python-tk@3.13`。

## 运行

```sh
./run.sh
# 或
/opt/homebrew/bin/python3.13 openconnect_gui.py
```

## Sudo 免密配置（推荐，一次即可）

openconnect 需要 root 权限配置路由和 DNS。推荐只对它开放免密：

```sh
sudo visudo -f /etc/sudoers.d/openconnect
```

写入一行（把 `用户名` 和路径换成你的，软件内「帮助 → Sudo 免密配置说明」可一键复制）：

```
用户名 ALL=(ALL) NOPASSWD: /opt/homebrew/bin/openconnect
```

不配置也能用：连接时会弹窗输入 Mac 管理员密码。

## 使用

1. 填写服务器地址（如 `vpn.example.com`）、选择协议、输入用户名密码
2. 点「连接」；若服务器要求 OTP/二次密码会自动弹窗
3. 「保存配置」后下次从左侧列表一键加载
4. 断开即自动恢复路由与 DNS

## 常见问题

| 问题 | 解决 |
| --- | --- |
| 连接后无法访问内网 | 检查日志中 `vpnc-script` 输出；确认 `/opt/homebrew/etc/vpnc/vpnc-script` 存在 |
| GlobalProtect 连不上 | 协议选 `gp`；若门户与网关地址不同，填网关地址 |
| 多用户组服务器 | 在「用户组」填组名，可跳过连接时的组选择菜单 |
| 证书错误 | 「高级选项 → CA 证书」选择公司根证书 |

## 安全说明

- 密码仅在勾选「记住密码」时写入 **macOS 钥匙串**
- 配置文件 `~/.openconnect-gui/profiles.json` 不含明文密码
