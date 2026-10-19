#!/bin/bash
set -e

# ==============================================================================
# Sing-Box WebUI Linux 一键卸载与环境清理脚本
# 特性:
#   1. 停止并注销 singbox-ui systemd 服务
#   2. 杀掉遗留的 sing-box 与面板进程
#   3. 清理安装目录 (/opt/singbox-ui)
#   4. 清理防火墙放行规则 (9622 / 2080)
#   5. 可选清理网络转发与 TUN 配置
# ==============================================================================

INSTALL_DIR="/opt/singbox-ui"
PORT=9622

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}====================================================================${NC}"
echo -e "${YELLOW}               Sing-Box WebUI 一键卸载与清理程序                   ${NC}"
echo -e "${CYAN}====================================================================${NC}"

# 1. 检查 root 权限
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}❌ 错误: 必须使用 root 或 sudo 权限运行此卸载脚本！${NC}"
   exit 1
fi

echo -e "\n${BLUE}[1/4] 正在停止并注销系统服务...${NC}"

# 停止并禁用 systemd 服务
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet singbox-ui 2>/dev/null; then
        systemctl stop singbox-ui || true
    fi
    if systemctl is-enabled --quiet singbox-ui 2>/dev/null; then
        systemctl disable singbox-ui || true
    fi
    if [ -f "/etc/systemd/system/singbox-ui.service" ]; then
        rm -f /etc/systemd/system/singbox-ui.service
        systemctl daemon-reload
    fi
fi

# 确保杀死所有可能残留的 sing-box 与 app.py 进程
pkill -9 -f "sing-box run" 2>/dev/null || true
pkill -9 -f "app.py --port" 2>/dev/null || true
echo -e "${GREEN}✔ 服务与相关后台进程已全部终止并注销${NC}"

# 2. 清理防火墙端口规则
echo -e "\n${BLUE}[2/4] 清理防火墙端口规则 (${PORT} / 2080) 与旁路由策略路由...${NC}"
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    ufw delete allow ${PORT}/tcp >/dev/null 2>&1 || true
    ufw delete allow 2080/tcp >/dev/null 2>&1 || true
    echo -e "${GREEN}✔ UFW 防火墙端口规则已移除${NC}"
elif command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
    firewall-cmd --remove-port=${PORT}/tcp --permanent >/dev/null 2>&1 || true
    firewall-cmd --remove-port=2080/tcp --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "${GREEN}✔ Firewalld 防火墙端口规则已移除${NC}"
else
    echo -e "${YELLOW}未检测到活动防火墙，跳过${NC}"
fi

# 清理旁路由透明网关残留: 策略路由 (iif -> table 2022) 与 DNS 劫持重定向规则
if command -v ip &> /dev/null; then
    while IFS= read -r iface; do
        [ -z "$iface" ] && continue
        case "$iface" in
            lo|tun0|docker*|veth*|br-*|virbr*|tun*) continue ;;
        esac
        ip -4 rule del iif "$iface" table 2022 2>/dev/null || true
        if command -v iptables &>/dev/null; then
            while iptables -C FORWARD -i "$iface" -o tun0 -j ACCEPT 2>/dev/null; do
                iptables -D FORWARD -i "$iface" -o tun0 -j ACCEPT 2>/dev/null || break
            done
            while iptables -C FORWARD -i tun0 -o "$iface" -j ACCEPT 2>/dev/null; do
                iptables -D FORWARD -i tun0 -o "$iface" -j ACCEPT 2>/dev/null || break
            done
        fi
    done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}')
    echo -e "${GREEN}✔ 旁路由策略路由规则 (table 2022) 已清理${NC}"
fi
if command -v iptables &> /dev/null; then
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    # Remove rules inserted by older releases; they opened all forwarding traffic.
    for legacy in "-i tun0 -j ACCEPT" "-o tun0 -j ACCEPT" "-j ACCEPT"; do
        while iptables -C FORWARD $legacy 2>/dev/null; do
            iptables -D FORWARD $legacy 2>/dev/null || break
        done
    done
    if iptables -S DOCKER-USER >/dev/null 2>&1; then
        for legacy in "-i tun0 -j ACCEPT" "-o tun0 -j ACCEPT" "-j ACCEPT"; do
            while iptables -C DOCKER-USER $legacy 2>/dev/null; do
                iptables -D DOCKER-USER $legacy 2>/dev/null || break
            done
        done
    fi
    echo -e "${GREEN}✔ DNS 劫持重定向规则已清理${NC}"
fi

# 3. 删除文件与安装目录
echo -e "\n${BLUE}[3/4] 删除程序文件与数据目录...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}✔ 已彻底删除目录: ${INSTALL_DIR}${NC}"
else
    echo -e "${YELLOW}目录 ${INSTALL_DIR} 不存在，跳过${NC}"
fi

# 4. 清理自启模块配置文件 (保留系统级 sysctl 转发以防影响宿主机其他容器/服务，如需清除可手动删除)
if [ -f "/etc/modules-load.d/singbox-tun.conf" ]; then
    rm -f /etc/modules-load.d/singbox-tun.conf
fi

echo -e "\n${BLUE}[4/4] 检查系统环境...${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "${GREEN}  🎉 卸载完成！Sing-Box WebUI 及其所有组件已从系统彻底清除。       ${NC}"
echo -e "${GREEN}====================================================================${NC}\n"
