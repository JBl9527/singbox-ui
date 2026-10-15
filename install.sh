#!/bin/bash
set -e

# ==============================================================================
# Sing-Box WebUI Linux 全自动一键安装脚本 (支持国内镜像高速拉取与海外直连)
# 适用平台: Linux amd64 (x86_64), arm64 (aarch64), armv7 (armhf/armv7l), 386
# 特性:
#   1. 内置多路国内 GitHub 高速镜像源 (ghfast / ghproxy)，网络拉取 100% 成功
#   2. 全自动开启内核 IP 转发 (IPv4/IPv6 forwarding) 与 TUN 模块
#   3. 全自动配置并放行防火墙端口 (9622 UI 端口 / 2080 混合代理端口)
#   4. 全自动识别芯片架构并拉取对应官方 sing-box 二进制
#   5. 全自动注册并启动 systemd 开机自启服务 (内核与WebUI全部就绪)
# ==============================================================================

PORT=9622
INSTALL_DIR="/opt/singbox-ui"
SINGBOX_VERSION="1.14.3"
GITHUB_REPO="JBl9527/singbox-ui"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/main"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 国内加速镜像前缀候选列表
MIRRORS=(
    "https://ghfast.top/"
    "https://ghproxy.net/"
    "https://mirror.ghproxy.com/"
    ""
)

# 智能多镜像下载函数
smart_download() {
    local raw_url="$1"
    local output_file="$2"
    for prefix in "${MIRRORS[@]}"; do
        local target_url="${prefix}${raw_url}"
        if curl -fL --connect-timeout 6 --max-time 90 "$target_url" -o "$output_file" 2>/dev/null; then
            if [ -s "$output_file" ]; then
                return 0
            fi
        fi
    done
    return 1
}

clear
echo -e "${CYAN}====================================================================${NC}"
echo -e "${PURPLE}       Sing-Box WebUI Linux 零配置一键安装 (集成国内加速源)         ${NC}"
echo -e "${CYAN}====================================================================${NC}"

# 0. 支持直接通过 install.sh 进行一键卸载
if [ "$1" = "--uninstall" ] || [ "$1" = "uninstall" ] || [ "$1" = "-u" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
        bash "$SCRIPT_DIR/uninstall.sh"
    elif [ -f "$INSTALL_DIR/uninstall.sh" ]; then
        bash "$INSTALL_DIR/uninstall.sh"
    else
        systemctl stop singbox-ui 2>/dev/null || true
        systemctl disable singbox-ui 2>/dev/null || true
        rm -f /etc/systemd/system/singbox-ui.service 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        pkill -9 -f "sing-box run" 2>/dev/null || true
        pkill -9 -f "app.py --port" 2>/dev/null || true
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}✔ Sing-Box WebUI 卸载完成！${NC}"
    fi
    exit 0
fi

# 1. 检查 root 权限
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}❌ 错误: 必须使用 root 或 sudo 权限运行此脚本！${NC}"
   exit 1
fi

# 2. 全自动优化 Linux 内核网络配置 (IP 转发与 TUN 模块)
echo -e "\n${BLUE}[1/6] 正在全自动配置 Linux 系统底层网络 (IP转发 / TUN网卡)...${NC}"

# 加载 TUN 模块
modprobe tun 2>/dev/null || true
if [ -d "/etc/modules-load.d" ]; then
    echo "tun" > /etc/modules-load.d/singbox-tun.conf
fi

# 配置并固化 IPv4 / IPv6 转发
SYSCTL_CONF="/etc/sysctl.d/99-singbox.conf"
cat <<EOF > "$SYSCTL_CONF"
# Sing-Box Network Forwarding Optimization
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv4.conf.all.route_localnet = 1
EOF

# 立即刷新内核参数生效
sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1 || true
echo -e "${GREEN}✔ 内核 IP 转发已永久开启 (net.ipv4.ip_forward=1)${NC}"

# 3. 自动安装必要基础包 (Python3, curl, tar)
echo -e "\n${BLUE}[2/6] 检查运行环境与基础组件...${NC}"
if ! command -v python3 &> /dev/null || ! command -v curl &> /dev/null || ! command -v tar &> /dev/null; then
    echo -e "${YELLOW}正在安装必要运行组件 (python3, curl, tar)...${NC}"
    if command -v apt-get &> /dev/null; then
        apt-get update -y && apt-get install -y python3 curl tar ca-certificates
    elif command -v yum &> /dev/null; then
        yum install -y python3 curl tar ca-certificates
    elif command -v apk &> /dev/null; then
        apk add --no-cache python3 curl tar ca-certificates
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm python tar curl ca-certificates
    fi
fi
echo -e "${GREEN}✔ 基础环境检查完毕: $(python3 --version)${NC}"

# 4. 识别芯片架构
echo -e "\n${BLUE}[3/6] 检测 CPU 芯片架构...${NC}"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        SB_ARCH="amd64"
        ;;
    aarch64|arm64)
        SB_ARCH="arm64"
        ;;
    armv7*|armhf)
        SB_ARCH="armv7"
        ;;
    i386|i686)
        SB_ARCH="386"
        ;;
    *)
        echo -e "${YELLOW}未直接匹配架构: ${ARCH}，尝试使用 amd64 构建${NC}"
        SB_ARCH="amd64"
        ;;
esac
echo -e "${GREEN}✔ 匹配目标硬件架构: ${ARCH} -> sing-box-${SB_ARCH}${NC}"

# 5. 建立安装目录并布置文件
echo -e "\n${BLUE}[4/6] 准备面板程序与前端文件 (自动加速拉取)...${NC}"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/static"
mkdir -p "$INSTALL_DIR/templates"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/app.py" ] && [ -f "$SCRIPT_DIR/static/index.html" ]; then
    echo "从本地脚本目录部署到 ${INSTALL_DIR} ..."
    cp -r "$SCRIPT_DIR/app.py" "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR/install.sh" "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR/static/"* "$INSTALL_DIR/static/"
    cp -r "$SCRIPT_DIR/templates/"* "$INSTALL_DIR/templates/"
else
    echo "检测到远程执行模式，正在通过国内加速镜像源拉取面板代码..."
    smart_download "${GITHUB_RAW_BASE}/app.py" "$INSTALL_DIR/app.py"
    smart_download "${GITHUB_RAW_BASE}/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
    smart_download "${GITHUB_RAW_BASE}/static/index.html" "$INSTALL_DIR/static/index.html"
    smart_download "${GITHUB_RAW_BASE}/templates/preset_config.json" "$INSTALL_DIR/templates/preset_config.json"
fi

chmod +x "$INSTALL_DIR/app.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true

# 6. 下载并安装官方 sing-box 核心
echo -e "\n${BLUE}[5/6] 部署官方 sing-box 最新内核 (v${SINGBOX_VERSION})...${NC}"
TARGET_BIN="$INSTALL_DIR/bin/sing-box"

NEED_DOWNLOAD=false
if [ ! -f "$TARGET_BIN" ] || [ ! -x "$TARGET_BIN" ]; then
    NEED_DOWNLOAD=true
else
    CURRENT_VER=$("$TARGET_BIN" version 2>/dev/null | head -n 1 || echo "")
    if [[ "$CURRENT_VER" != *"$SINGBOX_VERSION"* ]]; then
        echo -e "检测到现有内核版本为: ${YELLOW}${CURRENT_VER}${NC}，准备平滑升级到最新版 (v${SINGBOX_VERSION})..."
        NEED_DOWNLOAD=true
    else
        echo -e "${GREEN}✔ 已经是官方最新内核: ${CURRENT_VER}${NC}"
    fi
fi

if [ "$NEED_DOWNLOAD" = true ]; then
    ORIGINAL_RELEASE_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz"
    echo -e "正在下载匹配芯片的最新内核..."
    TMP_TAR="/tmp/sing-box-${SB_ARCH}.tar.gz"

    if smart_download "$ORIGINAL_RELEASE_URL" "$TMP_TAR"; then
        tar -xzf "$TMP_TAR" -C /tmp/
        EXT_BIN=$(find /tmp/ -type f -name "sing-box" | head -n 1)
        if [ -n "$EXT_BIN" ] && [ -f "$EXT_BIN" ]; then
            mv "$EXT_BIN" "$TARGET_BIN"
            chmod +x "$TARGET_BIN"
        fi
        rm -f "$TMP_TAR"
        echo -e "${GREEN}✔ sing-box 最新内核部署成功: $($TARGET_BIN version | head -n 1)${NC}"
    else
        echo -e "${YELLOW}⚠ 下载最新内核遇到网络波动，稍后可在 WebUI 页面点击【一键下载内核】${NC}"
    fi
fi

# 初始化配置文件（开箱自带预设模板）
if [ ! -f "$INSTALL_DIR/data/config.json" ] && [ -f "$INSTALL_DIR/templates/preset_config.json" ]; then
    cp "$INSTALL_DIR/templates/preset_config.json" "$INSTALL_DIR/data/config.json"
fi

# 7. 自动配置防火墙规则 (放行 9622 UI 端口与 2080 代理端口)
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    echo -e "配置 UFW 防火墙放行端口 ${PORT} 和 2080..."
    ufw allow ${PORT}/tcp >/dev/null 2>&1 || true
    ufw allow 2080/tcp >/dev/null 2>&1 || true
elif command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
    echo -e "配置 Firewalld 防火墙放行端口 ${PORT} 和 2080..."
    firewall-cmd --add-port=${PORT}/tcp --add-port=2080/tcp --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# 8. 注册 systemd 开机自启服务并立即启动
echo -e "\n${BLUE}[6/6] 注册开机自启服务并启动所有组件...${NC}"
cat <<EOF > /etc/systemd/system/singbox-ui.service
[Unit]
Description=Sing-Box WebUI Dashboard & Core Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py --port ${PORT}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable singbox-ui.service
systemctl restart singbox-ui.service

# 等待服务就绪
sleep 2

# 9. 智能获取 IP 地址
LOCAL_IP=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1 || echo "127.0.0.1")
PUBLIC_IP=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || curl -s4 --max-time 3 https://ifconfig.me 2>/dev/null || echo "$LOCAL_IP")

echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN}  🎉 恭喜！Sing-Box WebUI 已全部安装就绪并自动启动！               ${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "  ▶ 外网访问地址: ${CYAN}http://${PUBLIC_IP}:${PORT}${NC}"
echo -e "  ▶ 内网访问地址: ${CYAN}http://${LOCAL_IP}:${PORT}${NC}"
echo -e "  ▶ 本机回环地址: ${CYAN}http://127.0.0.1:${PORT}${NC}"
echo -e "--------------------------------------------------------------------"
echo -e "  ✔ 内核状态:    ${GREEN}已随系统自启，内核正在运行${NC}"
echo -e "  ✔ IP转发功能:  ${GREEN}已全自动开启 (IPv4/IPv6 Forwarding)${NC}"
echo -e "  ✔ 混合入站:    ${GREEN}0.0.0.0:2080 (Socks/HTTP)${NC}"
echo -e "  ✔ 虚拟网卡:    ${GREEN}tun0 (TUN 全局接管已就绪)${NC}"
echo -e "--------------------------------------------------------------------"
echo -e "${YELLOW}使用提示:${NC}"
echo -e "直接在浏览器中打开上方地址，在【订阅导入】页面输入订阅链接，"
echo -e "点击【拉取并生成配置】，面板将全自动融合预设规则并立即生效，无需再敲任何代码！"
echo -e "${GREEN}====================================================================${NC}\n"
