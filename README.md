# Sing-Box WebUI Dashboard

专为低功耗、性能较弱的 Linux 设备（ARM 电视盒子、斐讯N1、树莓派、低配 VPS、软路由等）打造的极轻量级 **Sing-Box** 图形化管理面板。

- **内核驱动**：以官方最新核心 [SagerNet/sing-box](https://github.com/sagernet/sing-box) 为核心
- **全自动系统调优**：安装时**全自动开启 Linux IPv4/IPv6 内核转发、自动加载 TUN 虚拟网卡驱动、自动放行防火墙端口**，无需再敲任何底层配置命令
- **全自动自启与运行**：安装完毕后内核与 WebUI 面板**全部自动启动**，并在开机时自动后台常驻
- **开箱即用流程**：部署完成后在浏览器输入 `http://IP:9622`，使用安装时显示的 WebUI 账号密码登录，再粘贴订阅链接或配置文件即可使用
- **多芯片架构适配**：原生自适应 `amd64` (x86_64)、`arm64` (aarch64)、`armv7` (armhf)、`386`
- **超低资源占用**：后端基于纯 Python 3 标准库（零 pip 依赖），单进程内存开销 < 15MB，待机 CPU 占用接近 0%

---

## ⚡ 一键极速安装（推荐）

### 🇨🇳 国内服务器极速安装（推荐国内机器使用）

使用国内高速反代加速源，彻底解决 GitHub 连接超时与内核下载缓慢问题：

```bash
bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/JBl9527/singbox-ui/main/install.sh)
```

备用镜像（若上述镜像繁忙可用此项）：
```bash
bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JBl9527/singbox-ui/main/install.sh)
```

### 🌍 海外 / 国际服务器直连安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/JBl9527/singbox-ui/main/install.sh)
```

> **提示**：如果你先使用 `git clone` 下载了源码，直接在项目根目录下运行：
> ```bash
> chmod +x install.sh
> sudo ./install.sh
> ```

---

## 🛠️ 安装脚本全自动完成的事项（无需手动输入代码）

1. **自动开启 Linux 底层网络转发**：
   - 永久开启 `net.ipv4.ip_forward = 1`
   - 永久开启 `net.ipv6.conf.all.forwarding = 1`
   - 固化至 `/etc/sysctl.d/99-singbox.conf`，系统重启依然有效
2. **自动加载并固化 TUN 驱动**：
   - 执行 `modprobe tun` 并将 `tun` 模块写入开机加载列表，确保护航 TUN 虚拟网卡全局代理
3. **自动放行防火墙**：
   - 智能识别 `ufw` 或 `firewalld`，自动放行 **9622** 端口（WebUI）和 **2080** 端口（混合代理入站）
4. **多芯片硬件架构自动检测与官方内核拉取**：
   - 自动检测 CPU 是 Intel/AMD 还是 ARM (ARM64/ARMv7)，自动下载匹配架构的官方 `sing-box` 二进制
5. **开箱自启机制**：
   - 自动生成 `singbox-ui.service` systemd 服务，配置开机自启
   - **安装完成后内核与 WebUI 全部自动启动**，并自动在终端打印出公网与内网 WebUI 访问链接

---

## 🚀 开箱使用步骤

1. 打开浏览器，访问安装完成后提示的地址：`http://你的服务器IP:9622`
2. 安装时可输入自定义 WebUI 密码（至少 12 个字符），并再次输入确认；直接按 Enter 则生成随机密码。随后使用安装输出的 `admin` 账号和密码登录。密码保存在 `/opt/singbox-ui/data/webui_password`，文件权限为 `600`；重新安装时会保留现有密码。

非交互安装可通过 `WEBUI_PASSWORD` 环境变量设置密码；未设置时会生成随机密码，并在安装完成信息中显示。
3. 进入 **【订阅导入与预设】** 页面：
   - 粘贴你的节点订阅链接（Subscription URL）
   - 保持勾选“融合预设模板”（自动注入 DNS 防污染分流、国内网站直连、自动优选节点组、TUN 网卡接管）
   - 点击 **【拉取并生成配置】**
4. 面板将自动拉取所有节点、合成完整规则并**自动重启内核生效**！
5. 切换到 **【节点选择】** 页面：
   - 直观查看所有节点卡片与协议类型（VMess / VLESS / Trojan / Shadowsocks / Hysteria2 等）
   - 点击“组内测速”实时查看各节点绿色延迟
   - 点击任意节点卡片即可**免重启动态热切换（Clash API）**，当前连接不断流！

---

## 📁 项目目录结构

```text
singbox-ui/
├── app.py                     # 后端守护进程（纯标准库，端口9622，内核自动接管）
├── install.sh                 # Linux 一键安装、多架构适配与底层网络自启脚本
├── run.sh                     # 快速本地调试启动脚本
├── uninstall.sh               # 一键卸载与环境清理脚本
├── static/
│   └── index.html             # 现代化极简 WebUI（含可视化节点选择、延迟测速、实时日志）
├── templates/
│   └── preset_config.json     # 预设高性能配置模板（含 Clash API、Fake-IP、TUN、Mixed、DNS、路由规则集）
├── bin/                       # sing-box 官方核心二进制目录
└── data/                      # 运行时 config.json 配置与数据存储
```

---

## 🗑️ 一键彻底卸载命令

如果你需要从系统彻底清除该面板及内核，可以使用以下任一方式：

### 方式一：GitHub 远程一行命令卸载（无需进入目录）

- **🇨🇳 国内机器推荐：**
  ```bash
  bash <(curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/JBl9527/singbox-ui/main/uninstall.sh)
  ```
- **🌍 海外机器直连：**
  ```bash
  bash <(curl -fsSL https://raw.githubusercontent.com/JBl9527/singbox-ui/main/uninstall.sh)
  ```

### 方式二：在已安装机器上本地运行
```bash
sudo bash /opt/singbox-ui/uninstall.sh
```
或者：
```bash
sudo bash /opt/singbox-ui/install.sh --uninstall
```

> 卸载程序将**全自动停止服务、注销开机自启、关闭后台内核、移除防火墙开放端口并彻底删除所有安装文件**。

---

## 🔧 常用后台命令

- **查看面板与内核状态**：`systemctl status singbox-ui`
- **重启服务**：`systemctl restart singbox-ui`
- **停止服务**：`systemctl stop singbox-ui`
- **查看实时输出日志**：`journalctl -u singbox-ui -f`
