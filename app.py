#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sing-Box WebUI Dashboard (sing-box 1.14.3 旁路由透明网关 & FakeIP 防回环 & AnyTLS 终极修复版)
轻量级、低功耗 CPU 友好型 Sing-box 管理面板与多格式订阅处理器
核心特性与修复:
  1. 彻底解决 TUN + FakeIP 下访问国外网站报 Connection reset by peer (Issue #2643 DNS 回环):
     - 将直连默认解析器 "ali" 升级为 DoH (https://223.5.5.5/dns-query，端口 443)，彻底避开 Linux TUN
       ip rule 9002 对 dport 53 的劫持，防止 sing-box 自身解析代理节点域名时被套入 FakeIP 回环
     - 自动提取所有代理节点的 server 域名注入 dns.rules 第一条强制走 "ali" 真实 IP 解析，绝不分配 FakeIP
     - route.rules 使用 logical OR (inbound=dns-in || protocol=dns || port=53) 优先劫持所有 DNS 请求，
       避免发往主路由 192.168.x.1:53 的 DNS 请求落入 ip_is_private 直连导致 GFW 污染重置
     - 启动/重启时自动清理旧 cache.db 中可能残留的错误 FakeIP 缓存
  2. 旁路由 53 端口 DNS 监听 + 内核参数 (rp_filter=0) 与 iptables FORWARD/MASQUERADE 全自动配置
  3. 完美支持 Sub-Store 订阅、AnyTLS 等全协议清洗及多线程并发测速
"""

import os
import re
import ssl
import sys
import gzip
import zlib
import json
import time
import socket
import struct
import random
import base64
import shutil
import tarfile
import ipaddress
import traceback
import urllib.request
import urllib.parse
import urllib.error
import platform
import subprocess
import threading
import argparse
from http.server import HTTPServer, ThreadingHTTPServer, SimpleHTTPRequestHandler
from collections import deque

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
PRESET_PATH = os.path.join(BASE_DIR, "templates", "preset_config.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")
BIN_DIR = os.path.join(BASE_DIR, "bin")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BIN_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

# 内存日志缓冲队列（最多保存300条）
LOG_BUFFER = deque(maxlen=300)

# 忽略 SSL 证书校验且绕过系统环境变量代理的 Opener
UNVERIFIED_SSL_CTX = ssl._create_unverified_context()
DIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=UNVERIFIED_SSL_CTX)
)

def append_log(msg: str):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    LOG_BUFFER.append(f"[{timestamp}] {msg}")

def ensure_tun_available() -> bool:
    """检测当前 Linux / 容器环境是否具备可用的 /dev/net/tun 设备"""
    if os.name == "nt":
        return True
    tun_path = "/dev/net/tun"
    if not os.path.exists(tun_path):
        try:
            subprocess.run(["modprobe", "tun"], capture_output=True, timeout=2)
        except Exception:
            pass
        if not os.path.exists(tun_path):
            try:
                os.makedirs("/dev/net", exist_ok=True)
                subprocess.run(["mknod", tun_path, "c", "10", "200"], capture_output=True, timeout=2)
                os.chmod(tun_path, 0o666)
            except Exception:
                pass

    if not os.path.exists(tun_path):
        return False

    try:
        fd = os.open(tun_path, os.O_RDWR)
        os.close(fd)
        return True
    except Exception:
        return False

def _get_gateway_ifaces():
    """
    获取旁路由模式下需要接管的局域网物理网卡列表:
    排除 lo / tun0 / docker / veth 等虚拟接口, 保留配置了私有 IPv4 地址的网卡。
    多网卡机器 (如 eth0 接 LAN、eth1 接 WAN) 会全部返回, 确保转发流量无遗漏。
    """
    ifaces = set()
    try:
        res = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=3)
        for line in res.stdout.splitlines():
            m = re.match(r"^\d+:\s+(\S+)\s+inet\s+(\S+)", line)
            if not m:
                continue
            name, addr = m.group(1), m.group(2)
            if name in ("lo", "tun0") or name.startswith(("docker", "veth", "br-", "virbr", "tun")):
                continue
            try:
                if ipaddress.ip_address(addr.split("/")[0]).is_private:
                    ifaces.add(name)
            except Exception:
                continue
    except Exception:
        pass
    # 兜底: 私有地址扫描无结果时, 回退到默认路由的出接口 (排除 tun0)
    if not ifaces:
        try:
            res = subprocess.run(["ip", "-4", "route", "show", "table", "main", "default"],
                                 capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                m = re.search(r"\bdev\s+(\S+)", line)
                if m and m.group(1) != "tun0":
                    ifaces.add(m.group(1))
        except Exception:
            pass
    return sorted(ifaces)


def verify_gateway_diversion(max_wait: int = 5) -> bool:
    """
    自检旁路由分流链路: table 2022 是否存在指向 tun0 的默认路由。
    sing-box TUN auto_route 启动成功后会自动写入该路由; 若缺失, 说明 TUN 未生效,
    局域网转发流量会走 main 表直连、完全绕过 sing-box 内核分流。
    返回 True 表示分流链路就绪。
    """
    if os.name == "nt" or not shutil.which("ip"):
        return True
    for _ in range(max_wait):
        try:
            res = subprocess.run(["ip", "route", "show", "table", "2022"],
                                 capture_output=True, text=True, timeout=3)
            if "dev tun0" in res.stdout:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def setup_gateway_network():
    """
    自动配置 Linux 单臂旁路由 / 透明网关底层内核参数与防火墙转发规则

    注意: ip rule / iptables 规则都是内存状态, 重启即丢失。install.sh 只在安装时配置一次,
    因此本函数在每次服务启动时都会重新全量恢复, 保证重启后旁路由分流依然生效。
    核心链路: 局域网转发流量 --(ip rule iif <lan> table 2022)--> tun0 --> sing-box 内核规则分流
    """
    if os.name == "nt":
        return
    sysctl_pairs = [
        "net.ipv4.ip_forward=1",
        "net.ipv4.conf.all.forwarding=1",
        "net.ipv4.conf.default.forwarding=1",
        "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.default.rp_filter=0",
        "net.ipv4.conf.tun0.rp_filter=0",
        "net.ipv4.conf.all.send_redirects=0",
        "net.ipv4.conf.default.send_redirects=0",
    ]
    for kv in sysctl_pairs:
        try:
            subprocess.run(["sysctl", "-w", kv], capture_output=True, timeout=2)
        except Exception:
            pass

    main_iface = ""
    try:
        res = subprocess.run(["ip", "-4", "route", "show", "table", "main", "default"], capture_output=True, text=True, timeout=2)
        m = re.search(r"\bdev\s+(\S+)", res.stdout)
        if m:
            main_iface = m.group(1)
    except Exception:
        pass

    if main_iface:
        try:
            subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{main_iface}.rp_filter=0"], capture_output=True, timeout=2)
            subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{main_iface}.send_redirects=0"], capture_output=True, timeout=2)
        except Exception:
            pass

    if shutil.which("iptables"):
        try:
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True, timeout=2)
            if main_iface:
                chk = subprocess.run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", main_iface, "-j", "MASQUERADE"], capture_output=True, timeout=2)
                if chk.returncode != 0:
                    subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", main_iface, "-j", "MASQUERADE"], capture_output=True, timeout=2)
            # FORWARD 放行 tun0 双向流量 (转发路径必经)
            for fwd_args in (["-I", "FORWARD", "-i", "tun0", "-j", "ACCEPT"],
                             ["-I", "FORWARD", "-o", "tun0", "-j", "ACCEPT"]):
                try:
                    subprocess.run(["iptables"] + fwd_args, capture_output=True, timeout=2)
                except Exception:
                    pass
            # DNS 劫持: 局域网所有 53 端口请求重定向到本机 53,
            # 由 sing-box dns-in (0.0.0.0:53) + hijack-dns 接管做 FakeIP 解析,
            # 否则局域网 DNS 直连会导致域名分流规则对转发流量失效
            for proto in ("udp", "tcp"):
                base = ["-t", "nat", "PREROUTING", "-p", proto, "--dport", "53",
                        "-j", "REDIRECT", "--to-ports", "53"]
                chk = subprocess.run(["iptables"] + ["-C"] + base, capture_output=True, timeout=2)
                if chk.returncode != 0:
                    ins = subprocess.run(["iptables"] + ["-I"] + base, capture_output=True, text=True, timeout=2)
                    if ins.returncode == 0:
                        append_log(f"DNS劫持规则已恢复({proto})")
                    else:
                        append_log(f"警告: DNS劫持规则写入失败({proto}): {(ins.stderr or '').strip()[:150]}")
                else:
                    append_log(f"DNS劫持规则已存在({proto}), 无需重复写入")
        except Exception:
            pass
    else:
        append_log("警告: 未找到 iptables 命令, 已跳过 FORWARD 放行/DNS劫持/MASQUERADE 规则配置; "
                   "请先安装 iptables (如 apt-get install -y iptables) 后重启服务")
    # === 旁路由分流核心: 策略路由 (重启丢失, 每次启动必须恢复) ===
    # sing-box TUN auto_route 只接管本机发出的流量 (table 2022), 转发流量默认走 main 表直连,
    # 必须用这条规则把"从局域网网卡进来的包"也送进 table 2022 -> tun0 -> sing-box 内核分流。
    # 缺了它, 局域网流量完全绕过 sing-box, 即"流量不经过内核分流"。
    if shutil.which("ip"):
        for lan_iface in _get_gateway_ifaces():
            try:
                # 先删后加, 保证幂等且优先级正确
                subprocess.run(["ip", "-4", "rule", "del", "iif", lan_iface, "table", "2022"],
                               capture_output=True, timeout=2)
                add = subprocess.run(["ip", "-4", "rule", "add", "iif", lan_iface, "table", "2022", "pref", "15000"],
                                     capture_output=True, timeout=2)
                if add.returncode == 0:
                    append_log(f"旁路由策略路由已恢复: iif {lan_iface} -> table 2022 (pref 15000)")
                else:
                    append_log(f"旁路由策略路由配置失败({lan_iface}): {(add.stderr or '').strip()[:120]}")
            except Exception as e:
                append_log(f"旁路由策略路由配置异常({lan_iface}): {e}")

VALID_PROXY_TYPES = {
    "anytls", "vless", "vmess", "shadowsocks", "trojan", "hysteria", "hysteria2",
    "tuic", "shadowtls", "naive", "snell", "tor", "ssh", "http", "socks"
}

TYPE_ALIASES = {
    "ss": "shadowsocks",
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "socks5": "socks",
    "socks5+tls": "socks",
    "http": "http",
    "https": "http",
}

COMMON_DIAL_FIELDS = {
    "detour", "bind_interface", "inet4_bind_address", "inet6_bind_address",
    "routing_mark", "reuse_addr", "connect_timeout", "tcp_fast_open",
    "tcp_multi_path", "udp_fragment", "domain_resolver", "network_strategy",
    "network_type", "fallback_network_type", "fallback_delay"
}

ALLOWED_OUTBOUND_FIELDS = {
    "anytls": {
        "type", "tag", "server", "server_port", "password",
        "idle_session_check_interval", "idle_session_timeout", "min_idle_session",
        "client_metadata", "tls"
    } | COMMON_DIAL_FIELDS,
    "vless": {
        "type", "tag", "server", "server_port", "uuid", "flow", "network",
        "tls", "multiplex", "transport", "packet_encoding"
    } | COMMON_DIAL_FIELDS,
    "vmess": {
        "type", "tag", "server", "server_port", "uuid", "security", "alter_id",
        "global_padding", "authenticated_length", "network", "tls",
        "packet_encoding", "multiplex", "transport"
    } | COMMON_DIAL_FIELDS,
    "trojan": {
        "type", "tag", "server", "server_port", "password", "network",
        "tls", "multiplex", "transport"
    } | COMMON_DIAL_FIELDS,
    "shadowsocks": {
        "type", "tag", "server", "server_port", "method", "password",
        "plugin", "plugin_opts", "network", "udp_over_tcp", "multiplex"
    } | COMMON_DIAL_FIELDS,
    "hysteria2": {
        "type", "tag", "server", "server_port", "server_ports", "hop_interval",
        "up_mbps", "down_mbps", "obfs", "password", "network", "tls", "brutal_debug"
    } | COMMON_DIAL_FIELDS,
    "hysteria": {
        "type", "tag", "server", "server_port", "server_ports", "hop_interval",
        "up", "up_mbps", "down", "down_mbps", "obfs", "auth", "auth_str",
        "network", "tls"
    } | COMMON_DIAL_FIELDS,
    "tuic": {
        "type", "tag", "server", "server_port", "uuid", "password",
        "congestion_control", "udp_relay_mode", "udp_over_stream",
        "zero_rtt_handshake", "heartbeat", "network", "tls"
    } | COMMON_DIAL_FIELDS,
    "socks": {
        "type", "tag", "server", "server_port", "version", "username",
        "password", "network", "udp_over_tcp", "tls"
    } | COMMON_DIAL_FIELDS,
    "http": {
        "type", "tag", "server", "server_port", "username", "password",
        "path", "headers", "tls"
    } | COMMON_DIAL_FIELDS,
}

CN_DOMAIN_SUFFIXES = [
    ".cn", ".baidu.com", ".qq.com", ".weixin.qq.com", ".wechat.com",
    ".taobao.com", ".tmall.com", ".alicdn.com", ".aliyun.com", ".alipay.com",
    ".jd.com", ".360buyimg.com", ".163.com", ".126.com", ".126.net", ".127.net",
    ".bilibili.com", ".hdslb.com", ".biliapi.net", ".douyin.com", ".bytedance.com",
    ".weibo.com", ".sina.com.cn", ".mi.com", ".xiaomi.com", ".zhihu.com",
    ".csdn.net", ".meituan.com", ".dianping.com", ".pinduoduo.com",
    ".ipip.net", ".cip.cc", ".10010.com", ".189.cn", ".10086.cn",
    ".ghfast.top", ".ghproxy.net"
]

# 内置 sing-box 1.14.3 标准旁路由预设模板
# 关键设计: "ali" 使用 https (DoH 443端口)，彻底避开 TUN 对 UDP 53 端口的自动劫持回环 (Issue #2643)

# ============ v2 数据层: DIY分组 / 节点选择 / 设置 / 节点快照 ============
GROUPS_PATH = os.path.join(DATA_DIR, "groups.json")
SELECTIONS_PATH = os.path.join(DATA_DIR, "selections.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
NODES_PATH = os.path.join(DATA_DIR, "nodes.json")

def _load_json_file(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return json.loads(json.dumps(default))

def _save_json_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def load_groups():
    d = _load_json_file(GROUPS_PATH, {"groups": []})
    groups = d.get("groups", [])
    groups.sort(key=lambda g: g.get("order", 0))
    return {"groups": groups}

def save_groups(groups):
    for i, g in enumerate(groups):
        g["order"] = i
    _save_json_file(GROUPS_PATH, {"groups": groups})

def new_group_id():
    import uuid as _uuid
    return "g-" + _uuid.uuid4().hex[:8]

def load_selections():
    return _load_json_file(SELECTIONS_PATH, {})

def save_selections(sel):
    _save_json_file(SELECTIONS_PATH, sel)

def load_settings():
    return _load_json_file(SETTINGS_PATH, {"quic_block": True})

def save_settings(s):
    _save_json_file(SETTINGS_PATH, s)

def load_nodes():
    return _load_json_file(NODES_PATH, [])

def save_nodes(nodes):
    _save_json_file(NODES_PATH, nodes)

def _v2_base_config():
    """v2 最小化基础配置: 仅中国内外分流骨架"""
    return {
        "log": {"level": "info", "timestamp": True},
        "experimental": {
            "cache_file": {"enabled": True, "path": "cache.db", "store_fakeip": True, "store_dns": True},
            "clash_api": {"external_controller": "0.0.0.0:9090", "external_ui": "ui", "default_mode": "Rule"},
        },
        "dns": {
            "servers": [
                {"type": "udp", "tag": "ali", "server": "223.5.5.5", "server_port": 53},
                {"type": "local", "tag": "local"},
                {"type": "https", "tag": "remote", "server": "1.1.1.1", "server_port": 443,
                 "path": "/dns-query", "domain_resolver": "ali", "detour": "默认代理"},
                {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
            ],
            "rules": [
                # D1: 拒 HTTPS/SVCB (防 ECH 加密 SNI)
                {"query_type": ["HTTPS", "SVCB"], "action": "reject"},
                # D4: 国内域名 -> 国内DNS 拿真实IP (直连更快, 不走 fakeip)
                {"rule_set": "geosite-cn", "query_type": ["A", "AAAA"],
                 "action": "route", "server": "ali"},
                # D8: 国外/小众未知域名 -> FakeIP (由分流规则按域名路由)
                {"inbound": ["dns-in", "tun-in"], "query_type": ["A", "AAAA"],
                 "action": "route", "server": "fakeip", "rewrite_ttl": 1},
            ],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {"type": "direct", "tag": "dns-in", "listen": "0.0.0.0", "listen_port": 53},
            {"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080},
            {"type": "tun", "tag": "tun-in", "interface_name": "tun0",
             "address": ["172.19.0.1/30"], "mtu": 1500, "auto_route": True,
             "strict_route": False, "stack": "mixed", "endpoint_independent_nat": True},
        ],
        "outbounds": [],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "ali",
            "final": "漏网之鱼",
            "rule_set": [
                {"tag": "geosite-cn", "type": "remote", "format": "binary",
                 "url": "https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                 "download_detour": "直连"},
                {"tag": "geoip-cn", "type": "remote", "format": "binary",
                 "url": "https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                 "download_detour": "直连"},
            ],
            "rules": [],
        },
    }

def load_preset_dict():
    """v2: 返回最小化基础配置模板 (不 sanitize, 因 outbounds 为空时 sanitize 会改写 final)"""
    return _v2_base_config()

def _get_effective_config_dict():
    """读取 config.json, 不存在时返回 v2 最小化基础配置"""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return _v2_base_config()


def is_ip_address(val: str) -> bool:
    if not val:
        return False
    try:
        ipaddress.ip_address(val.strip("[]"))
        return True
    except ValueError:
        return False

def to_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "on")
    return False

def classify_nodes_by_region(nodes):
    """根据节点 tag 智能归类地区, 返回 [(地区名, [节点tag...])] (仅含非空地区, 按固定顺序)"""
    regions = [
        ("香港", ["hk", "hongkong", "hong kong", "香港", "🇭🇰"]),
        ("台湾", ["tw", "taiwan", "台湾", "台北", "🇹🇼"]),
        ("日本", ["jp", "japan", "日本", "东京", "大阪", "🇯🇵"]),
        ("狮城", ["sg", "singapore", "新加坡", "狮城", "🇸🇬"]),
        ("美国", ["us", "united states", "america", "美国", "洛杉矶", "圣何塞", "硅谷", "西雅图", "纽约", "🇺🇸", "🇺🇲"]),
        ("韩国", ["kr", "korea", "韩国", "首尔", "🇰🇷"]),
        ("英国", ["uk", "britain", "england", "英国", "伦敦", "🇬🇧"]),
        ("德国", ["de", "germany", "german", "德国", "法兰克福", "🇩🇪"]),
        ("法国", ["fr", "france", "french", "法国", "巴黎", "🇫🇷"]),
        ("荷兰", ["nl", "netherlands", "dutch", "荷兰", "阿姆斯特丹", "🇳🇱"]),
        ("加拿大", ["ca", "canada", "加拿大", "多伦多", "🇨🇦"]),
        ("澳大利亚", ["au", "australia", "澳大利亚", "悉尼", "🇦🇺"]),
    ]
    buckets = {name: [] for name, _ in regions}
    for n in nodes:
        tag_lower = n.get("tag", "").lower()
        for r_name, keywords in regions:
            if any(k in tag_lower for k in keywords):
                buckets[r_name].append(n["tag"])
                break
    return [(name, tags) for name, tags in [(n, buckets[n]) for n, _ in regions] if tags]

def sanitize_tls_object(tls_in, server_host="", top_sni=None, top_insecure=None, top_alpn=None, top_fp=None, force_enable=False):
    """构建并清洗符合 sing-box 1.14 规范的出站 TLS 对象"""
    if isinstance(tls_in, dict):
        tls_obj = dict(tls_in)
    elif to_bool(tls_in) or force_enable or top_sni or top_insecure is not None or top_alpn or top_fp:
        tls_obj = {"enabled": True}
    else:
        return None

    tls_obj["enabled"] = True

    if "sni" in tls_obj and "server_name" not in tls_obj:
        tls_obj["server_name"] = tls_obj.pop("sni")
    else:
        tls_obj.pop("sni", None)

    if top_sni and not tls_obj.get("server_name"):
        tls_obj["server_name"] = str(top_sni).strip()
    elif not tls_obj.get("server_name") and server_host and not is_ip_address(server_host):
        tls_obj["server_name"] = server_host

    if not tls_obj.get("server_name"):
        tls_obj.pop("server_name", None)

    if top_insecure is not None and "insecure" not in tls_obj:
        tls_obj["insecure"] = to_bool(top_insecure)
    elif "insecure" in tls_obj:
        tls_obj["insecure"] = to_bool(tls_obj["insecure"])

    if top_alpn is not None and "alpn" not in tls_obj:
        if isinstance(top_alpn, str):
            tls_obj["alpn"] = [x.strip() for x in top_alpn.split(",") if x.strip()]
        elif isinstance(top_alpn, list):
            tls_obj["alpn"] = [str(x).strip() for x in top_alpn if str(x).strip()]
    elif "alpn" in tls_obj and isinstance(tls_obj["alpn"], str):
        tls_obj["alpn"] = [x.strip() for x in tls_obj["alpn"].split(",") if x.strip()]

    if top_fp and "utls" not in tls_obj:
        tls_obj["utls"] = {"enabled": True, "fingerprint": str(top_fp).strip()}
    elif isinstance(tls_obj.get("utls"), dict):
        tls_obj["utls"]["enabled"] = to_bool(tls_obj["utls"].get("enabled", True))

    allowed_tls_keys = {
        "enabled", "disable_sni", "server_name", "insecure", "alpn",
        "min_version", "max_version", "cipher_suites", "certificate",
        "certificate_path", "certificate_public_key_sha256", "client_certificate",
        "client_certificate_path", "client_key", "client_key_path", "fragment",
        "fragment_fallback_delay", "record_fragment", "ech", "utls", "reality"
    }
    for k in list(tls_obj.keys()):
        if k not in allowed_tls_keys:
            tls_obj.pop(k, None)

    return tls_obj

def normalize_proxy_outbound(ob: dict):
    """标准化单个代理出站节点，兼容 Sing-Box JSON、Sub-Store JSON 与 Clash 字典格式"""
    if not isinstance(ob, dict):
        return None

    raw_type = str(ob.get("type", "")).strip().lower()
    otype = TYPE_ALIASES.get(raw_type, raw_type)
    if otype not in VALID_PROXY_TYPES:
        return ob

    ob = dict(ob)
    ob["type"] = otype

    if "tag" not in ob and "name" in ob:
        ob["tag"] = str(ob.pop("name")).strip()
    else:
        ob.pop("name", None)

    if "server_port" not in ob and "port" in ob:
        ob["server_port"] = ob.pop("port")
    else:
        ob.pop("port", None)

    if "server_port" in ob:
        try:
            ob["server_port"] = int(ob["server_port"])
        except Exception:
            ob["server_port"] = 443
    else:
        ob["server_port"] = 443

    server_host = str(ob.get("server", "")).strip()
    if not ob.get("tag") or not server_host:
        return None
    ob["server"] = server_host

    top_sni = ob.pop("sni", None) or ob.pop("servername", None) or ob.pop("server_name", None) or ob.pop("peer", None)
    top_insecure = ob.pop("skip-cert-verify", None)
    if top_insecure is None:
        top_insecure = ob.pop("insecure", None)
    if top_insecure is None:
        top_insecure = ob.pop("allow_insecure", None)
    if top_insecure is None:
        top_insecure = ob.pop("allowInsecure", None)
    top_alpn = ob.pop("alpn", None)
    top_fp = ob.pop("client-fingerprint", None) or ob.pop("fingerprint", None) or ob.pop("fp", None)
    raw_tls = ob.pop("tls", None)

    raw_net = str(ob.pop("network", "") or "").strip().lower()
    ws_opts = ob.pop("ws-opts", None)
    grpc_opts = ob.pop("grpc-opts", None)
    reality_opts = ob.pop("reality-opts", None)

    if "transport" not in ob:
        if raw_net == "ws" or isinstance(ws_opts, dict):
            ws_opts = ws_opts if isinstance(ws_opts, dict) else {}
            t_obj = {"type": "ws", "path": str(ws_opts.get("path") or ob.pop("ws-path", "/") or "/")}
            headers = ws_opts.get("headers") or ob.pop("ws-headers", None)
            if isinstance(headers, dict) and headers:
                t_obj["headers"] = headers
            ob["transport"] = t_obj
        elif raw_net == "grpc" or isinstance(grpc_opts, dict):
            grpc_opts = grpc_opts if isinstance(grpc_opts, dict) else {}
            ob["transport"] = {
                "type": "grpc",
                "service_name": str(grpc_opts.get("grpc-service-name") or grpc_opts.get("service_name") or "")
            }

    if otype == "anytls":
        if not ob.get("password"):
            ob["password"] = str(ob.pop("uuid", "") or ob.pop("username", "") or "")
        else:
            ob["password"] = str(ob["password"])

        tls_obj = sanitize_tls_object(
            raw_tls, server_host=server_host,
            top_sni=top_sni, top_insecure=top_insecure,
            top_alpn=top_alpn, top_fp=top_fp, force_enable=True
        )
        ob["tls"] = tls_obj

        for dur_key, clash_dur_key in (
            ("idle_session_check_interval", "idle-session-check-interval"),
            ("idle_session_timeout", "idle-session-timeout")
        ):
            if clash_dur_key in ob and dur_key not in ob:
                ob[dur_key] = ob.pop(clash_dur_key)
            if dur_key in ob and isinstance(ob[dur_key], (int, float)):
                ob[dur_key] = f"{int(ob[dur_key])}s"

        if "min-idle-session" in ob and "min_idle_session" not in ob:
            ob["min_idle_session"] = ob.pop("min-idle-session")
        if "min_idle_session" in ob:
            try:
                ob["min_idle_session"] = int(ob["min_idle_session"])
            except Exception:
                ob.pop("min_idle_session", None)

        if "client-metadata" in ob and "client_metadata" not in ob:
            ob["client_metadata"] = str(ob.pop("client-metadata"))

    elif otype in ("trojan", "hysteria2", "tuic"):
        if "password" in ob:
            ob["password"] = str(ob["password"])
        tls_obj = sanitize_tls_object(
            raw_tls, server_host=server_host,
            top_sni=top_sni, top_insecure=top_insecure,
            top_alpn=top_alpn, top_fp=top_fp, force_enable=True
        )
        ob["tls"] = tls_obj
        if otype == "hysteria2" and isinstance(ob.get("obfs"), str):
            obfs_type = ob.pop("obfs")
            if obfs_type and obfs_type != "none":
                ob["obfs"] = {"type": obfs_type, "password": str(ob.pop("obfs-password", ""))}
        if otype == "tuic":
            if "congestion-controller" in ob and "congestion_control" not in ob:
                ob["congestion_control"] = ob.pop("congestion-controller")
            if "udp-relay-mode" in ob and "udp_relay_mode" not in ob:
                ob["udp_relay_mode"] = ob.pop("udp-relay-mode")

    elif otype in ("vless", "vmess"):
        if otype == "vmess":
            if "cipher" in ob and "security" not in ob:
                ob["security"] = str(ob.pop("cipher") or "auto")
            ob.setdefault("security", "auto")
            if "alterId" in ob and "alter_id" not in ob:
                ob["alter_id"] = int(ob.pop("alterId") or 0)
        if "packet-encoding" in ob and "packet_encoding" not in ob:
            ob["packet_encoding"] = ob.pop("packet-encoding")

        need_tls = bool(raw_tls or isinstance(reality_opts, dict) or top_sni or (otype == "vless" and ob.get("flow")))
        tls_obj = sanitize_tls_object(
            raw_tls, server_host=server_host,
            top_sni=top_sni, top_insecure=top_insecure,
            top_alpn=top_alpn, top_fp=top_fp, force_enable=need_tls
        )
        if isinstance(reality_opts, dict) and tls_obj:
            tls_obj["reality"] = {
                "enabled": True,
                "public_key": str(reality_opts.get("public-key") or reality_opts.get("public_key") or ""),
                "short_id": str(reality_opts.get("short-id") or reality_opts.get("short_id") or "")
            }
            if "utls" not in tls_obj:
                tls_obj["utls"] = {"enabled": True, "fingerprint": str(top_fp or "chrome")}
        if tls_obj:
            ob["tls"] = tls_obj

    elif otype == "shadowsocks":
        if "cipher" in ob and "method" not in ob:
            ob["method"] = str(ob.pop("cipher"))
        if "password" in ob:
            ob["password"] = str(ob["password"])

    allowed_keys = ALLOWED_OUTBOUND_FIELDS.get(otype)
    if allowed_keys:
        for k in list(ob.keys()):
            if k not in allowed_keys:
                ob.pop(k, None)

    return ob

def migrate_legacy_dns_server(srv: dict, fakeip_cfg: dict):
    """将旧版 DNS Server ({'address': '...'}) 迁移为 sing-box 1.12 / 1.14+ Typed DNS Server 格式"""
    if not isinstance(srv, dict):
        return None, None

    s = dict(srv)
    tag = s.get("tag", "")

    s.pop("strategy", None)
    s.pop("address_strategy", None)
    s.pop("address_fallback_delay", None)
    if "address_resolver" in s:
        if "domain_resolver" not in s:
            s["domain_resolver"] = s.pop("address_resolver")
        else:
            s.pop("address_resolver", None)

    # 关键升级: 将直连 223.5.5.5 的 UDP 53 升级为 HTTPS (DoH 443)，防止被 TUN dport 53 规则劫持形成回环
    if s.get("server") == "223.5.5.5" and s.get("type") in ("udp", "tcp", None) and not s.get("detour"):
        return {
            "type": "https",
            "tag": tag or "ali",
            "server": "223.5.5.5",
            "server_port": 443,
            "path": "/dns-query"
        }, None

    if "type" in s and "address" not in s:
        stype = str(s["type"]).lower()
        s["type"] = stype
        if stype in ("local", "fakeip"):
            s.pop("detour", None)
            s.pop("domain_resolver", None)
            if stype == "fakeip":
                s.setdefault("inet4_range", fakeip_cfg.get("inet4_range", "198.18.0.0/15"))
                s.setdefault("inet6_range", fakeip_cfg.get("inet6_range", "fc00::/18"))
        elif s.get("detour") in ("direct", "直连"):
            s.pop("detour", None)
        return s, None

    addr = str(s.pop("address", "")).strip()
    if not addr and "type" not in s:
        return None, None

    if addr.startswith("rcode://") or s.get("type") == "rcode":
        return None, tag

    if addr == "fakeip" or s.get("type") == "fakeip" or tag == "fakeip":
        return {
            "type": "fakeip",
            "tag": tag or "fakeip",
            "inet4_range": s.get("inet4_range") or fakeip_cfg.get("inet4_range", "198.18.0.0/15"),
            "inet6_range": s.get("inet6_range") or fakeip_cfg.get("inet6_range", "fc00::/18")
        }, None

    if addr == "local" or s.get("type") == "local":
        res = {"type": "local"}
        if tag:
            res["tag"] = tag
        return res, None

    if addr.startswith("dhcp://") or s.get("type") == "dhcp":
        res = {"type": "dhcp"}
        if tag:
            res["tag"] = tag
        iface = addr[len("dhcp://"):] if addr.startswith("dhcp://") else s.get("interface", "")
        if iface and iface != "auto":
            res["interface"] = iface
        return res, None

    if "://" in addr:
        parsed = urllib.parse.urlsplit(addr)
        scheme = parsed.scheme.lower()
        if scheme == "doh":
            scheme = "https"
        if scheme not in ("udp", "tcp", "tls", "https", "h3", "quic"):
            scheme = "udp"
        host = parsed.hostname or addr
        port = parsed.port
        path = parsed.path
        s["type"] = scheme
        s["server"] = host
        if port:
            s["server_port"] = int(port)
        if scheme in ("https", "h3") and path and path != "/":
            s["path"] = path
    else:
        if addr in ("223.5.5.5", "223.6.6.6"):
            return {
                "type": "https",
                "tag": tag or "ali",
                "server": addr,
                "server_port": 443,
                "path": "/dns-query"
            }, None
        s["type"] = s.get("type", "udp").lower()
        if ":" in addr and not is_ip_address(addr):
            host, _, port_str = addr.rpartition(":")
            s["server"] = host.strip("[]")
            try:
                s["server_port"] = int(port_str)
            except ValueError:
                pass
        else:
            s["server"] = addr.strip("[]")

    if s.get("detour") in ("direct", "直连"):
        s.pop("detour", None)

    return s, None

def _harden_route_rules(rules, direct_tag, main_proxy_tag, valid_tags):
    """加固已有的 route.rules：保留调用方的精细化分流意图，仅确保三条安全不变量：
    1) 首条为 sniff；2) hijack-dns 出现在首个 ip_is_private 规则之前（防 DNS 回环）；
    3) 所有 outbound 引用必须有效，无效的一律改写（私有流量→直连，其余→主代理组）。"""
    clean = [dict(r) for r in rules if isinstance(r, dict)]
    if not clean or clean[0].get("action") != "sniff":
        clean.insert(0, {"action": "sniff"})
    first_private = next((i for i, r in enumerate(clean) if r.get("ip_is_private") is True), None)
    scope = clean[:first_private] if first_private is not None else clean
    if not any(r.get("action") == "hijack-dns" for r in scope):
        hijack_rule = {"type": "logical", "mode": "or",
                       "rules": [{"protocol": "dns"}, {"port": 53}],
                       "action": "hijack-dns"}
        clean.insert(first_private if first_private is not None else 1, hijack_rule)
    for r in clean:
        ob = r.get("outbound")
        if isinstance(ob, str) and ob not in valid_tags:
            r["outbound"] = direct_tag if r.get("ip_is_private") else main_proxy_tag
    return clean


def sanitize_singbox_dict(cfg_dict, force_disable_tun: bool = False):
    """全面清理与修复配置，彻底解决 TUN + FakeIP 下的 DNS 回环重置问题"""
    if not isinstance(cfg_dict, dict):
        return cfg_dict

    tun_supported = False if force_disable_tun else ensure_tun_available()

    # --- 1. 修复 Inbounds ---
    has_tun = False
    has_dns_in = False
    inbound_tags_for_fakeip = []
    clean_inbounds = []

    for ib in cfg_dict.get("inbounds", []):
        if not isinstance(ib, dict):
            continue
        ib = dict(ib)
        ib.pop("sniff", None)
        ib.pop("sniff_override_destination", None)
        ib.pop("sniff_timeout", None)
        ib.pop("domain_strategy", None)
        ib.pop("udp_fragment", None)

        if ib.get("type") == "direct" and ib.get("listen_port") in (53, 5353):
            has_dns_in = True
            ib_tag = ib.get("tag") or "dns-in"
            ib["tag"] = ib_tag
            inbound_tags_for_fakeip.append(ib_tag)

        if ib.get("type") == "tun":
            if not tun_supported:
                continue
            has_tun = True
            ib_tag = ib.get("tag") or "tun-in"
            ib["tag"] = ib_tag
            inbound_tags_for_fakeip.append(ib_tag)
            ib.pop("gso", None)
            if "inet4_address" in ib:
                val = ib.pop("inet4_address")
                if "address" not in ib:
                    ib["address"] = [val] if isinstance(val, str) else list(val)
            if "inet6_address" in ib:
                val6 = ib.pop("inet6_address")
                ib.setdefault("address", [])
                if isinstance(ib["address"], str):
                    ib["address"] = [ib["address"]]
                if isinstance(val6, list):
                    ib["address"].extend(val6)
                elif isinstance(val6, str):
                    ib["address"].append(val6)
            for old_k, new_k in (
                ("inet4_route_address", "route_address"),
                ("inet6_route_address", "route_address"),
                ("inet4_route_exclude_address", "route_exclude_address"),
                ("inet6_route_exclude_address", "route_exclude_address"),
            ):
                if old_k in ib:
                    v = ib.pop(old_k)
                    ib.setdefault(new_k, [])
                    if isinstance(v, list):
                        ib[new_k].extend(v)
                    elif isinstance(v, str):
                        ib[new_k].append(v)

        clean_inbounds.append(ib)

    if has_tun and not has_dns_in:
        clean_inbounds.insert(0, {
            "type": "direct",
            "tag": "dns-in",
            "listen": "0.0.0.0",
            "listen_port": 53
        })
        has_dns_in = True
        if "dns-in" not in inbound_tags_for_fakeip:
            inbound_tags_for_fakeip.append("dns-in")

    if not any(ib.get("type") == "mixed" for ib in clean_inbounds):
        clean_inbounds.append({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "0.0.0.0",
            "listen_port": 2080
        })

    cfg_dict["inbounds"] = clean_inbounds
    valid_inbound_tags = {ib.get("tag") for ib in clean_inbounds if ib.get("tag")}

    # --- 2. 净化 Outbounds 并收集所有代理节点的服务器域名 (防止代理节点域名被 FakeIP 污染) ---
    valid_outbounds = []
    valid_tags = set()
    proxy_tags = []
    proxy_server_domains = set()
    removed_dns_tags = {"dns", "dns-out"}
    removed_block_tags = {"block", "block-out", "拒绝"}
    direct_tag = None

    raw_outbounds = cfg_dict.get("outbounds", [])
    if not isinstance(raw_outbounds, list):
        raw_outbounds = []

    for ob in raw_outbounds:
        if not isinstance(ob, dict):
            continue
        raw_type = str(ob.get("type", "")).strip().lower()
        otype = TYPE_ALIASES.get(raw_type, raw_type)
        tag = str(ob.get("tag", "") or ob.get("name", "")).strip()

        if otype == "dns":
            if tag:
                removed_dns_tags.add(tag)
            continue
        if otype == "block":
            if tag:
                removed_block_tags.add(tag)
            continue

        if otype in ("fallback", "loadbalance"):
            ob = dict(ob)
            otype = "urltest"
            ob["type"] = "urltest"

        if otype == "direct":
            ob = dict(ob)
            ob["type"] = "direct"
            ob["tag"] = tag or "直连"
            ob.pop("override_address", None)
            ob.pop("override_port", None)
            ob.pop("domain_strategy", None)
            if direct_tag is None:
                direct_tag = ob["tag"]
            valid_outbounds.append(ob)
            valid_tags.add(ob["tag"])
        elif otype in ("selector", "urltest"):
            ob = dict(ob)
            ob["type"] = otype
            if not tag:
                tag = "自动选择" if otype == "urltest" else "默认代理"
                ob["tag"] = tag
            if otype == "urltest":
                ob.pop("default", None)
            valid_outbounds.append(ob)
            valid_tags.add(tag)
        elif otype in VALID_PROXY_TYPES:
            norm_ob = normalize_proxy_outbound(ob)
            if norm_ob and norm_ob.get("tag"):
                valid_outbounds.append(norm_ob)
                valid_tags.add(norm_ob["tag"])
                proxy_tags.append(norm_ob["tag"])
                srv_host = str(norm_ob.get("server", "")).strip()
                if srv_host and not is_ip_address(srv_host):
                    proxy_server_domains.add(srv_host.lower())

    if direct_tag is None:
        direct_tag = "直连"
        valid_outbounds.append({"type": "direct", "tag": direct_tag})
        valid_tags.add(direct_tag)

    has_group = any(ob.get("type") in ("selector", "urltest") for ob in valid_outbounds)
    if not has_group:
        auto_group = {
            "type": "urltest",
            "tag": "自动选择",
            "outbounds": list(proxy_tags) if proxy_tags else [direct_tag],
            "url": "http://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 50
        }
        select_group = {
            "type": "selector",
            "tag": "默认代理",
            "outbounds": ["自动选择"] + list(proxy_tags) + [direct_tag],
            "default": "自动选择"
        }
        valid_outbounds = [select_group, auto_group] + valid_outbounds
        valid_tags.update(["默认代理", "自动选择"])

    referenced_proxies = set()
    for ob in valid_outbounds:
        if ob.get("type") in ("selector", "urltest"):
            referenced_proxies.update(ob.get("outbounds", []))
    unreferenced_proxies = [t for t in proxy_tags if t not in referenced_proxies]

    for ob in valid_outbounds:
        otype = ob.get("type")
        if otype in ("selector", "urltest"):
            g_tag = ob.get("tag", "")
            raw_nodes = ob.get("outbounds", [])
            if not isinstance(raw_nodes, list):
                raw_nodes = []

            if g_tag in ("自动选择", "手动选择", "节点选择", "Proxy", "GLOBAL", "auto-fast"):
                for p_tag in proxy_tags:
                    if p_tag not in raw_nodes:
                        raw_nodes.append(p_tag)
            elif unreferenced_proxies and g_tag in ("默认代理", "proxy"):
                for p_tag in unreferenced_proxies:
                    if p_tag not in raw_nodes:
                        raw_nodes.append(p_tag)

            clean_nodes = []
            for n in raw_nodes:
                if n in valid_tags and n != g_tag and n not in clean_nodes:
                    clean_nodes.append(n)
            if not clean_nodes:
                clean_nodes = [direct_tag]
            ob["outbounds"] = clean_nodes

            if otype == "selector":
                if ob.get("default") not in clean_nodes:
                    ob["default"] = clean_nodes[0]
            else:
                ob.pop("default", None)

    cfg_dict["outbounds"] = valid_outbounds

    main_proxy_tag = "默认代理" if "默认代理" in valid_tags else (
        next((ob["tag"] for ob in valid_outbounds if ob.get("type") in ("selector", "urltest")), direct_tag)
    )

    # --- 3. 修复 DNS 配置 (DoH 443 防回环 + 代理节点域名白名单直连解析) ---
    dns_cfg = cfg_dict.get("dns")
    if not isinstance(dns_cfg, dict):
        dns_cfg = _v2_base_config()["dns"]
        cfg_dict["dns"] = dns_cfg

    legacy_fakeip = dns_cfg.pop("fakeip", None)
    fakeip_cfg = legacy_fakeip if isinstance(legacy_fakeip, dict) else {}
    dns_cfg.pop("independent_cache", None)
    dns_cfg["strategy"] = "ipv4_only"

    raw_servers = dns_cfg.get("servers", [])
    if not isinstance(raw_servers, list):
        raw_servers = []

    new_servers = []
    dns_server_tags = set()
    removed_rcode_tags = set()
    fakeip_server_tags = set()
    direct_dns_tag = None

    for srv in raw_servers:
        migrated_srv, rcode_tag = migrate_legacy_dns_server(srv, fakeip_cfg)
        if rcode_tag:
            removed_rcode_tags.add(rcode_tag)
            continue
        if migrated_srv:
            stag = migrated_srv.get("tag", "")
            if not stag:
                stag = f"dns-{len(new_servers) + 1}"
                migrated_srv["tag"] = stag
            if migrated_srv.get("type") == "fakeip":
                if not has_tun:
                    fakeip_server_tags.add(stag)
                    continue
                fakeip_server_tags.add(stag)
            if "detour" in migrated_srv and migrated_srv["detour"] not in valid_tags:
                migrated_srv["detour"] = main_proxy_tag
            new_servers.append(migrated_srv)
            dns_server_tags.add(stag)
            if direct_dns_tag is None and migrated_srv.get("type") in ("https", "tls", "udp", "tcp") and not migrated_srv.get("detour") and is_ip_address(str(migrated_srv.get("server", ""))):
                direct_dns_tag = stag

    if has_tun and (fakeip_cfg.get("enabled") or not fakeip_server_tags) and not any(s.get("type") == "fakeip" for s in new_servers):
        new_servers.append({
            "type": "fakeip",
            "tag": "fakeip",
            "inet4_range": fakeip_cfg.get("inet4_range", "198.18.0.0/15"),
            "inet6_range": fakeip_cfg.get("inet6_range", "fc00::/18")
        })
        dns_server_tags.add("fakeip")
        fakeip_server_tags.add("fakeip")

    if direct_dns_tag is None:
        direct_dns_tag = "ali" if "ali" not in dns_server_tags else "ali-doh"
        new_servers.insert(0, {
            "type": "https",
            "tag": direct_dns_tag,
            "server": "223.5.5.5",
            "server_port": 443,
            "path": "/dns-query"
        })
        dns_server_tags.add(direct_dns_tag)

    for s in new_servers:
        if "domain_resolver" in s:
            dr = s["domain_resolver"]
            dr_tag = dr.get("server") if isinstance(dr, dict) else dr
            if dr_tag not in dns_server_tags or dr_tag == s.get("tag"):
                s["domain_resolver"] = direct_dns_tag

    dns_cfg["servers"] = new_servers

    # --- 4. 修复 Route 与国内外分流规则集 (geosite-cn / geoip-cn) ---
    route_cfg = cfg_dict.get("route")
    if not isinstance(route_cfg, dict):
        route_cfg = {}
        cfg_dict["route"] = route_cfg

    route_cfg.pop("geoip", None)
    route_cfg.pop("geosite", None)

    if has_tun:
        route_cfg["auto_detect_interface"] = True

    cur_ddr = route_cfg.get("default_domain_resolver")
    cur_ddr_tag = cur_ddr.get("server") if isinstance(cur_ddr, dict) else cur_ddr
    if not cur_ddr_tag or cur_ddr_tag not in dns_server_tags or cur_ddr_tag in fakeip_server_tags:
        route_cfg["default_domain_resolver"] = direct_dns_tag

    if route_cfg.get("final") not in valid_tags:
        route_cfg["final"] = main_proxy_tag

    raw_rs = route_cfg.get("rule_set", [])
    if not isinstance(raw_rs, list):
        raw_rs = []

    clean_rs = []
    valid_rule_sets = set()
    for rs in raw_rs:
        if not isinstance(rs, dict) or not rs.get("tag"):
            continue
        rs = dict(rs)
        if "download_detour" in rs and rs["download_detour"] not in valid_tags:
            rs["download_detour"] = direct_tag
        clean_rs.append(rs)
        if isinstance(rs["tag"], list):
            valid_rule_sets.update(rs["tag"])
        else:
            valid_rule_sets.add(rs["tag"])

    for default_rs in _v2_base_config()["route"]["rule_set"]:
        if default_rs["tag"] not in valid_rule_sets:
            rs_copy = dict(default_rs)
            rs_copy["download_detour"] = direct_tag
            clean_rs.append(rs_copy)
            valid_rule_sets.add(rs_copy["tag"])

    route_cfg["rule_set"] = clean_rs

    # 构建防回环 dns.rules:
    # 第一优先级: 所有代理节点自身的 server 域名强制走 direct_dns_tag ("ali" DoH)，绝不进 FakeIP
    # 第二优先级: geosite-cn 与国内常见域名后缀走 direct_dns_tag ("ali" DoH)
    # 第三优先级: 来自 tun-in / dns-in 的 A/AAAA 查询走 fakeip
    clean_dns_rules = []
    # 第零优先级: 拒绝 HTTPS/SVCB 类型查询，迫使客户端回退到 A/AAAA 查询。
    # 否则客户端拿到 ECH 配置后会加密 TLS SNI，网关将无法按域名分流
    # (典型如 *.googleapis.com 走 final 而非 Google 组)，只能看到 IP。
    clean_dns_rules.append({
        "query_type": ["HTTPS", "SVCB"],
        "action": "reject"
    })
    if proxy_server_domains:
        clean_dns_rules.append({
            "domain": sorted(list(proxy_server_domains)),
            "action": "route",
            "server": direct_dns_tag
        })
    if "geosite-cn" in valid_rule_sets:
        clean_dns_rules.append({
            "rule_set": ["geosite-cn"],
            "action": "route",
            "server": direct_dns_tag
        })
    clean_dns_rules.append({
        "domain_suffix": CN_DOMAIN_SUFFIXES,
        "action": "route",
        "server": direct_dns_tag
    })
    if has_tun and fakeip_server_tags:
        f_tag = sorted(list(fakeip_server_tags))[0]
        clean_dns_rules.append({
            "inbound": [t for t in inbound_tags_for_fakeip if t in valid_inbound_tags],
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": f_tag,
            "rewrite_ttl": 1
        })

    dns_cfg["rules"] = clean_dns_rules

    if dns_cfg.get("final") not in dns_server_tags or dns_cfg.get("final") in fakeip_server_tags:
        remote_tag = next((s["tag"] for s in new_servers if s.get("type") not in ("fakeip", "local") and s["tag"] != direct_dns_tag), direct_dns_tag)
        dns_cfg["final"] = remote_tag

    # 构建标准顺序的 route.rules:
    # 1. sniff
    # 2. logical OR (inbound=dns-in || protocol=dns || port=53) => hijack-dns (必须在 ip_is_private 之前！)
    # 3. ip_is_private => 直连
    # 4. 国内域名与 geosite-cn / geoip-cn => 直连
    hijack_subrules = [{"protocol": "dns"}, {"port": 53}]
    if "dns-in" in valid_inbound_tags:
        hijack_subrules.insert(0, {"inbound": ["dns-in"]})

    standard_route_rules = [
        {"action": "sniff"},
        {
            "type": "logical",
            "mode": "or",
            "rules": hijack_subrules,
            "action": "hijack-dns"
        },
        {
            "ip_is_private": True,
            "outbound": direct_tag
        },
        {
            "domain_suffix": CN_DOMAIN_SUFFIXES,
            "outbound": direct_tag
        }
    ]
    if "geosite-cn" in valid_rule_sets or "geoip-cn" in valid_rule_sets:
        standard_route_rules.append({
            "rule_set": [x for x in ("geosite-cn", "geoip-cn") if x in valid_rule_sets],
            "outbound": direct_tag
        })

    existing_rules = route_cfg.get("rules")
    if isinstance(existing_rules, list) and any(isinstance(r, dict) for r in existing_rules):
        # 调用方自带精细化分流规则(如预设模板的 AI/YouTube/Google 分组): 保留意图，仅做安全加固
        route_cfg["rules"] = _harden_route_rules(existing_rules, direct_tag, main_proxy_tag, valid_tags)
    else:
        route_cfg["rules"] = standard_route_rules

    # --- 5. 修复 Experimental ---
    exp_cfg = cfg_dict.get("experimental")
    if isinstance(exp_cfg, dict):
        cf = exp_cfg.get("cache_file")
        if isinstance(cf, dict) and "store_rdrc" in cf:
            val = cf.pop("store_rdrc")
            cf.setdefault("store_dns", val)

    return cfg_dict

def sanitize_config_file(filepath, force_disable_tun: bool = False):
    """就地净化已有配置文件"""
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        data = sanitize_singbox_dict(data, force_disable_tun=force_disable_tun)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        append_log(f"净化配置异常: {e}")

def clear_stale_cache_files():
    """清理可能缓存了错误 FakeIP 映射的旧 cache.db 文件"""
    for cpath in (
        os.path.join(BASE_DIR, "cache.db"),
        os.path.join(DATA_DIR, "cache.db"),
        "/opt/singbox-ui/cache.db",
        "/opt/singbox-ui/data/cache.db"
    ):
        try:
            if os.path.exists(cpath):
                os.remove(cpath)
        except Exception:
            pass

# ==============================================================================
# 强健网络拉取引擎 (解决 Sub-Store 500 / Cloudflare 403 / 自签证书 / DNS 污染与死锁)
# ==============================================================================

def normalize_url_string(raw_url: str) -> str:
    """安全规范化包含中文或已编码字符的订阅 URL，防止 UnicodeEncodeError"""
    u = raw_url.strip().strip("'\"")
    parsed = urllib.parse.urlsplit(u)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
    else:
        userinfo, hostport = "", netloc

    if ":" in hostport and not hostport.endswith("]"):
        host, port = hostport.rsplit(":", 1)
        host_ascii = host.encode("idna").decode("ascii")
        netloc_clean = f"{host_ascii}:{port}"
    else:
        netloc_clean = hostport.encode("idna").decode("ascii")

    if userinfo:
        netloc_clean = f"{userinfo}@{netloc_clean}"

    clean_path = urllib.parse.quote(urllib.parse.unquote(parsed.path), safe="/:@!$&'()*+,;=-._~")
    clean_query = urllib.parse.quote(urllib.parse.unquote(parsed.query), safe="=/:@!$&'()*+,;-._~?")
    return urllib.parse.urlunsplit((scheme, netloc_clean, clean_path, clean_query, ""))

def resolve_ipv4_via_public_dns(hostname: str) -> str:
    """当系统 /etc/resolv.conf 因 TUN 停止而失效时，直接通过公共 UDP DNS (223.5.5.5 / 119.29.29.29) 解析 IPv4"""
    if is_ip_address(hostname):
        return hostname
    for dns_ip in ("223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"):
        try:
            tid = random.randint(1, 65534)
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            qname = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in hostname.strip(".").split(".")) + b"\x00"
            question = qname + struct.pack(">HH", 1, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(header + question, (dns_ip, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
            ancount = struct.unpack(">H", data[6:8])[0]
            idx = 12
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            idx += 5
            for _ in range(ancount):
                if idx >= len(data):
                    break
                if (data[idx] & 0xC0) == 0xC0:
                    idx += 2
                else:
                    while idx < len(data) and data[idx] != 0:
                        idx += data[idx] + 1
                    idx += 1
                rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
                idx += 10
                if rtype == 1 and rclass == 1 and rdlen == 4:
                    return socket.inet_ntoa(data[idx:idx + 4])
                idx += rdlen
        except Exception:
            continue
    return ""

def http_fetch_single(url: str, ua: str, timeout: int = 15):
    """优先使用 curl (-4 强制 IPv4、-k 忽略自签证书、--noproxy '*')，失败时公共 DNS + Python 兜底"""
    norm_url = normalize_url_string(url)
    parsed = urllib.parse.urlsplit(norm_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    last_error = ""

    curl_bin = shutil.which("curl")
    if curl_bin:
        cmd = [
            curl_bin, "-fsSLk", "-4", "--noproxy", "*",
            "--connect-timeout", "8", "--max-time", str(timeout),
            "-A", ua,
            "-H", "Accept: */*",
            norm_url
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=timeout + 3)
            if res.returncode == 0 and res.stdout:
                return res.stdout.decode("utf-8", errors="ignore"), None
            err_msg = res.stderr.decode("utf-8", errors="ignore").strip()
            last_error = f"curl({res.returncode}): {err_msg}"
            if res.returncode in (6, 7, 28) and host and not is_ip_address(host):
                resolved_ip = resolve_ipv4_via_public_dns(host)
                if resolved_ip:
                    cmd_resolve = [
                        curl_bin, "-fsSLk", "-4", "--noproxy", "*",
                        "--connect-timeout", "8", "--max-time", str(timeout),
                        "--resolve", f"{host}:{port}:{resolved_ip}",
                        "-A", ua,
                        "-H", "Accept: */*",
                        norm_url
                    ]
                    res2 = subprocess.run(cmd_resolve, capture_output=True, timeout=timeout + 3)
                    if res2.returncode == 0 and res2.stdout:
                        return res2.stdout.decode("utf-8", errors="ignore"), None
        except Exception as e:
            last_error = f"curl异常: {e}"

    try:
        req = urllib.request.Request(
            norm_url,
            headers={
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate"
            }
        )
        with DIRECT_OPENER.open(req, timeout=timeout) as resp:
            raw_bytes = resp.read()
            encoding = (resp.headers.get("Content-Encoding") or "").lower()
            if encoding == "gzip" or raw_bytes[:2] == b"\x1f\x8b":
                raw_bytes = gzip.decompress(raw_bytes)
            elif encoding == "deflate":
                try:
                    raw_bytes = zlib.decompress(raw_bytes)
                except zlib.error:
                    raw_bytes = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
            return raw_bytes.decode("utf-8", errors="ignore"), None
    except urllib.error.HTTPError as he:
        err_body = ""
        try:
            err_body = he.read().decode("utf-8", errors="ignore")[:120].strip()
        except Exception:
            pass
        last_error = f"HTTP {he.code} ({he.reason})" + (f": {err_body}" if err_body else "")
    except Exception as e:
        last_error = str(e)

    return "", last_error

def add_query_param(url: str, key: str, val: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    q_list = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    q_dict = dict(q_list)
    q_dict[key] = val
    new_query = urllib.parse.urlencode(q_dict)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

def fetch_and_parse_subscription(sub_url: str):
    """针对 Sub-Store 与各类机场面板的多策略智能订阅拉取器"""
    norm_url = normalize_url_string(sub_url)
    parsed = urllib.parse.urlsplit(norm_url)
    is_substore = "/download/" in parsed.path or "/api/file/" in parsed.path
    has_target = "target=" in parsed.query.lower()

    attempts = []
    if is_substore and not has_target:
        attempts = [
            (add_query_param(norm_url, "target", "JSON"), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            (add_query_param(norm_url, "target", "ClashMeta"), "mihomo/1.19.0"),
            (add_query_param(norm_url, "target", "URI"), "v2rayNG/1.8.23"),
            (norm_url, "v2rayNG/1.8.23"),
            (norm_url, "mihomo/1.19.0"),
            (add_query_param(norm_url, "target", "sing-box"), "sing-box 1.14.3"),
        ]
    else:
        attempts = [
            (norm_url, "mihomo/1.19.0"),
            (norm_url, "v2rayNG/1.8.23"),
            (norm_url, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            (norm_url, "sing-box 1.14.3"),
        ]

    best_full_cfg = None
    best_nodes = []
    errors = []

    for target_url, ua in attempts:
        text, err = http_fetch_single(target_url, ua, timeout=15)
        if err or not text:
            if err:
                errors.append(f"[{ua.split('/')[0]}] {err}")
            continue

        full_cfg, nodes = parse_subscription_payload(text)
        if nodes:
            has_anytls = any(n.get("type") == "anytls" for n in nodes)
            if len(nodes) > len(best_nodes):
                best_full_cfg, best_nodes = full_cfg, nodes
            if has_anytls:
                return full_cfg, nodes, None
        elif full_cfg and not best_full_cfg:
            best_full_cfg = full_cfg

    if best_nodes or best_full_cfg:
        return best_full_cfg, best_nodes, None

    err_summary = "；".join(errors[:3]) if errors else "返回内容为空或无法识别节点格式"
    return None, [], err_summary

# ==============================================================================
# 订阅列表持久化 (支撑前端"多订阅管理与一键切换")
# 存储: DATA_DIR/subscriptions.json -> {"subscriptions": [...], "active_id": "..."}
# ==============================================================================
SUBS_PATH = os.path.join(DATA_DIR, "subscriptions.json")


def _now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _new_sub_id():
    return f"{int(time.time() * 1000):x}{random.randint(0, 0xFFFF):04x}"


def _load_subscriptions():
    default = {"subscriptions": [], "active_id": ""}
    try:
        if os.path.exists(SUBS_PATH):
            with open(SUBS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("subscriptions", [])
                data.setdefault("active_id", "")
                if not isinstance(data["subscriptions"], list):
                    data["subscriptions"] = []
                return data
    except Exception as e:
        append_log(f"读取订阅列表失败: {e}")
    return default


def _save_subscriptions(store):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SUBS_PATH, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        append_log(f"保存订阅列表失败: {e}")
        return False


def _parse_subscription_input(input_text):
    """解析订阅输入(URL 或直接粘贴的节点文本)，返回 (full_cfg, valid_external, err_msg)，不写配置。"""
    input_text = (input_text or "").strip()
    if not input_text:
        return None, [], "订阅链接或节点内容不能为空"
    if re.match(r"^https?://", input_text, re.I):
        append_log(f"正在拉取远程订阅: {input_text[:100]}")
        return fetch_and_parse_subscription(input_text)
    append_log("正在解析直接粘贴的节点链接/订阅文本...")
    full_cfg, valid_external = parse_subscription_payload(input_text)
    return full_cfg, valid_external, ""


def _subscription_parse_failed(full_cfg, valid_external, err_msg):
    return (err_msg and not valid_external and not full_cfg) or (not valid_external and not full_cfg)


def _build_and_write_config(full_cfg, valid_external, use_preset):
    """用解析结果构建并写入 config.json，返回 (config_str, node_count, anytls_count)。
    v2: 始终用最小化构建器; 节点快照存 data/nodes.json 供分组变更时重建; 重建前捕获当前选择。"""
    capture_live_selections()
    save_nodes(valid_external)
    if use_preset or not full_cfg:
        final_config, node_count = build_config_with_preset(valid_external)
    else:
        final_config = sanitize_singbox_dict(full_cfg)
        node_count = len(valid_external or [])
    final_config_str = json.dumps(final_config, indent=2, ensure_ascii=False)
    if os.path.exists(CONFIG_PATH):
        try:
            shutil.copy(CONFIG_PATH, os.path.join(DATA_DIR, "config.json.bak"))
        except Exception:
            pass
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(final_config_str)
    anytls_count = sum(1 for n in valid_external if n.get("type") == "anytls")
    return final_config_str, node_count, anytls_count


def _apply_subscription_record(rec, preparsed=None):
    """应用一条订阅记录: 重建配置 + 清理缓存 + 重启核心。
    preparsed 可选 (full_cfg, valid_external)，避免重复拉取。返回 (ok, message, config_str)。"""
    if preparsed is not None:
        full_cfg, valid_external = preparsed
    else:
        full_cfg, valid_external, err_msg = _parse_subscription_input(rec.get("url", ""))
        if _subscription_parse_failed(full_cfg, valid_external, err_msg):
            msg = f"订阅应用失败: {err_msg or '未能从订阅中提取到有效节点'}"
            append_log(msg)
            return False, msg, ""
    clear_stale_cache_files()
    config_str, node_count, anytls_count = _build_and_write_config(
        full_cfg, valid_external, rec.get("use_preset", True))
    rec["node_count"] = node_count
    rec["anytls_count"] = anytls_count
    rec["updated_at"] = _now_str()
    ok, restart_msg = manager.restart()
    status_note = "核心已重启生效" if ok else f"但核心启动异常: {restart_msg}"
    anytls_info = f"(含 {anytls_count} 个 AnyTLS 节点)" if anytls_count else ""
    msg = f"订阅「{rec.get('name') or '未命名'}」已应用，共载入 {node_count} 个节点{anytls_info}，{status_note}。"
    append_log(msg)
    return ok, msg, config_str

# ==============================================================================
# 多格式订阅解析器 (支持 Sing-Box JSON / Sub-Store JSON / Base64 URI / Clash YAML)
# ==============================================================================

def decode_base64_flexible(text: str) -> str:
    s = text.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.b64decode(s).decode("utf-8", errors="ignore")

def parse_proxy_uri(uri: str):
    """解析单条节点分享链接 (支持 anytls://, vless://, trojan://, vmess://, ss://, hysteria2://, hy2://, tuic://)"""
    uri = uri.strip()
    if not uri or "://" not in uri:
        return None

    scheme, _ = uri.split("://", 1)
    scheme = scheme.lower()

    try:
        if scheme == "vmess":
            b64_part = uri[len("vmess://"):].split("#", 1)[0]
            vdata = json.loads(decode_base64_flexible(b64_part))
            tag = str(vdata.get("ps") or vdata.get("remarks") or f"vmess-{vdata.get('add', '')}").strip()
            server = str(vdata.get("add", "")).strip()
            port = int(vdata.get("port", 443))
            uuid = str(vdata.get("id", "")).strip()
            aid = int(vdata.get("aid", 0) or 0)
            scy = str(vdata.get("scy", "auto") or "auto")
            net = str(vdata.get("net", "tcp") or "tcp").lower()
            tls_str = str(vdata.get("tls", "")).lower()
            sni = str(vdata.get("sni") or vdata.get("host") or "").strip()

            ob = {
                "type": "vmess",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "security": scy,
                "alter_id": aid
            }
            if tls_str == "tls":
                ob["tls"] = {"enabled": True, "server_name": sni or server}
            if net == "ws":
                ob["transport"] = {
                    "type": "ws",
                    "path": str(vdata.get("path") or "/"),
                    "headers": {"Host": str(vdata.get("host") or sni or server)}
                }
            elif net == "grpc":
                ob["transport"] = {
                    "type": "grpc",
                    "service_name": str(vdata.get("path") or "")
                }
            return normalize_proxy_outbound(ob)

        parsed = urllib.parse.urlsplit(uri)
        tag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
        query = urllib.parse.parse_qs(parsed.query)
        qget = lambda k, default="": query.get(k, [default])[0]

        if scheme == "ss":
            raw_body = uri[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
            if "@" in raw_body:
                user_b64, host_port = raw_body.rsplit("@", 1)
                if ":" in user_b64:
                    method, password = urllib.parse.unquote(user_b64).split(":", 1)
                else:
                    decoded_user = decode_base64_flexible(user_b64)
                    method, password = decoded_user.split(":", 1)
                h_split = urllib.parse.urlsplit(f"http://{host_port}")
                server = h_split.hostname
                port = h_split.port or 8388
            else:
                decoded_all = decode_base64_flexible(raw_body)
                user_part, host_port = decoded_all.rsplit("@", 1)
                method, password = user_part.split(":", 1)
                h_split = urllib.parse.urlsplit(f"http://{host_port}")
                server = h_split.hostname
                port = h_split.port or 8388
            return normalize_proxy_outbound({
                "type": "shadowsocks",
                "tag": tag or f"ss-{server}:{port}",
                "server": server,
                "server_port": int(port),
                "method": method,
                "password": password
            })

        server = parsed.hostname or ""
        port = parsed.port or 443
        username = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")

        if not server:
            return None
        if not tag:
            tag = f"{scheme}-{server}:{port}"

        sni = qget("sni") or qget("peer") or qget("serverName") or qget("servername")
        insecure = to_bool(qget("insecure") or qget("allowInsecure") or qget("allow_insecure") or qget("skip-cert-verify"))
        alpn = qget("alpn")
        fp = qget("fp") or qget("fingerprint") or qget("client-fingerprint")

        if scheme == "anytls":
            auth_pwd = f"{username}:{password}" if password else (username or qget("password"))
            ob = {
                "type": "anytls",
                "tag": tag,
                "server": server,
                "server_port": int(port),
                "password": auth_pwd,
                "sni": sni,
                "insecure": insecure,
                "alpn": alpn,
                "fp": fp
            }
            if qget("client_metadata"):
                ob["client_metadata"] = qget("client_metadata")
            return normalize_proxy_outbound(ob)

        elif scheme == "vless":
            ob = {
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": int(port),
                "uuid": username,
                "sni": sni,
                "insecure": insecure,
                "alpn": alpn,
                "fp": fp
            }
            flow = qget("flow")
            if flow:
                ob["flow"] = flow
            security = (qget("security") or "none").lower()
            if security in ("tls", "reality"):
                ob["tls"] = True
                if security == "reality":
                    ob["reality-opts"] = {
                        "public-key": qget("pbk"),
                        "short-id": qget("sid")
                    }
            net_type = (qget("type") or "tcp").lower()
            if net_type == "ws":
                ob["transport"] = {
                    "type": "ws",
                    "path": qget("path") or "/",
                    "headers": {"Host": qget("host") or sni or server}
                }
            elif net_type == "grpc":
                ob["transport"] = {
                    "type": "grpc",
                    "service_name": qget("serviceName") or qget("path")
                }
            return normalize_proxy_outbound(ob)

        elif scheme == "trojan":
            auth_pwd = f"{username}:{password}" if password else username
            ob = {
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": int(port),
                "password": auth_pwd,
                "sni": sni,
                "insecure": insecure,
                "alpn": alpn,
                "fp": fp,
                "tls": True
            }
            net_type = (qget("type") or "tcp").lower()
            if net_type == "ws":
                ob["transport"] = {
                    "type": "ws",
                    "path": qget("path") or "/",
                    "headers": {"Host": qget("host") or sni or server}
                }
            return normalize_proxy_outbound(ob)

        elif scheme in ("hysteria2", "hy2"):
            auth_pwd = f"{username}:{password}" if password else (username or qget("password"))
            ob = {
                "type": "hysteria2",
                "tag": tag,
                "server": server,
                "server_port": int(port),
                "password": auth_pwd,
                "sni": sni,
                "insecure": insecure,
                "alpn": alpn,
                "tls": True
            }
            obfs = qget("obfs")
            if obfs and obfs != "none":
                ob["obfs"] = {"type": obfs, "password": qget("obfs-password")}
            return normalize_proxy_outbound(ob)

        elif scheme == "tuic":
            return normalize_proxy_outbound({
                "type": "tuic",
                "tag": tag,
                "server": server,
                "server_port": int(port),
                "uuid": username,
                "password": password or qget("password"),
                "congestion_control": qget("congestion_control") or "bbr",
                "sni": sni,
                "insecure": insecure,
                "alpn": alpn,
                "tls": True
            })
    except Exception as e:
        append_log(f"解析节点链接失败 ({uri[:30]}...): {e}")
    return None

def parse_subscription_payload(raw_text: str):
    """智能解析订阅响应内容，返回 (parsed_full_singbox_dict_or_None, valid_proxy_outbounds_list)"""
    raw_text = raw_text.strip().lstrip("\ufeff")
    if not raw_text:
        return None, []

    try:
        parsed_json = json.loads(raw_text)
        if isinstance(parsed_json, dict):
            if "outbounds" in parsed_json and isinstance(parsed_json["outbounds"], list):
                nodes = []
                for ob in parsed_json["outbounds"]:
                    if not isinstance(ob, dict):
                        continue
                    otype = TYPE_ALIASES.get(str(ob.get("type", "")).lower(), str(ob.get("type", "")).lower())
                    if otype in VALID_PROXY_TYPES:
                        norm = normalize_proxy_outbound(ob)
                        if norm:
                            nodes.append(norm)
                return parsed_json, nodes
            elif "proxies" in parsed_json and isinstance(parsed_json["proxies"], list):
                nodes = [normalize_proxy_outbound(p) for p in parsed_json["proxies"] if isinstance(p, dict)]
                return None, [n for n in nodes if n and n.get("type") in VALID_PROXY_TYPES]
        elif isinstance(parsed_json, list):
            nodes = [normalize_proxy_outbound(p) for p in parsed_json if isinstance(p, dict)]
            return None, [n for n in nodes if n and n.get("type") in VALID_PROXY_TYPES]
    except Exception:
        pass

    candidate_text = raw_text
    if "://" not in candidate_text and "proxies:" not in candidate_text:
        try:
            decoded = decode_base64_flexible(candidate_text)
            if "://" in decoded or "proxies:" in decoded or decoded.strip().startswith(("{", "[")):
                return parse_subscription_payload(decoded)
        except Exception:
            pass

    uri_scheme_pattern = re.compile(r"^(anytls|vless|vmess|trojan|ss|hysteria2|hy2|tuic|socks5?|http)://", re.I)
    lines = [l.strip() for l in candidate_text.splitlines() if l.strip()]
    uri_lines = [l for l in lines if uri_scheme_pattern.match(l)]
    if uri_lines:
        nodes = []
        seen_tags = set()
        for l in uri_lines:
            node = parse_proxy_uri(l)
            if node and node.get("tag"):
                base_tag = node["tag"]
                idx = 2
                while node["tag"] in seen_tags:
                    node["tag"] = f"{base_tag}-{idx}"
                    idx += 1
                seen_tags.add(node["tag"])
                nodes.append(node)
        if nodes:
            return None, nodes

    if "proxies:" in candidate_text:
        nodes = []
        in_proxies = False
        current_item = {}
        for line in candidate_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.match(r"^proxies\s*:", stripped):
                in_proxies = True
                continue
            if in_proxies and not line.startswith((" ", "\t", "-")):
                break
            if not in_proxies:
                continue

            if stripped.startswith("-") and "{" in stripped and "}" in stripped:
                if current_item:
                    n = normalize_proxy_outbound(current_item)
                    if n and n.get("type") in VALID_PROXY_TYPES:
                        nodes.append(n)
                    current_item = {}
                brace_body = stripped[stripped.find("{") + 1:stripped.rfind("}")]
                item_dict = {}
                for part in re.split(r",(?![^\[]*\])", brace_body):
                    if ":" in part:
                        k, v = part.split(":", 1)
                        k = k.strip().strip("'\"")
                        v = v.strip().strip("'\"")
                        if v.startswith("[") and v.endswith("]"):
                            v = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
                        item_dict[k] = v
                n = normalize_proxy_outbound(item_dict)
                if n and n.get("type") in VALID_PROXY_TYPES:
                    nodes.append(n)
                continue

            if stripped.startswith("-"):
                if current_item:
                    n = normalize_proxy_outbound(current_item)
                    if n and n.get("type") in VALID_PROXY_TYPES:
                        nodes.append(n)
                current_item = {}
                rest = stripped[1:].strip()
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    current_item[k.strip().strip("'\"")] = v.strip().strip("'\"")
            elif ":" in stripped and current_item is not None:
                k, v = stripped.split(":", 1)
                current_item[k.strip().strip("'\"")] = v.strip().strip("'\"")

        if current_item:
            n = normalize_proxy_outbound(current_item)
            if n and n.get("type") in VALID_PROXY_TYPES:
                nodes.append(n)
        if nodes:
            return None, nodes

    return None, []

def _v2_selector(tag, members, default=None):
    ob = {"type": "selector", "tag": tag, "outbounds": list(members)}
    valid = [m for m in members if m]
    if default and default in valid:
        ob["default"] = default
    elif valid:
        ob["default"] = valid[0]
    return ob


# 订阅节点 tag 黑名单: 命中则视为信息节点(官网/流量/套餐/到期等)直接丢弃, 不计入节点
NODE_TAG_BLOCKLIST = [
    "官网", "剩余", "流量", "套餐", "免费", "订阅", "全球直连", "到期时间",
    "expire", "traffic",
]
# "GB" 单独处理: 仅当 tag 含数字+GB (如 100GB) 时视为流量信息节点, 避免误伤正常节点名
import re as _re
_GB_INFO_PATTERN = _re.compile(r"\d\s*gb", _re.I)

def _is_blocked_node_tag(tag: str) -> bool:
    t = (tag or "").lower()
    if any(kw.lower() in t for kw in NODE_TAG_BLOCKLIST):
        return True
    if _GB_INFO_PATTERN.search(t):
        return True
    return False

# 内置常用规则集 (DIY 分组下拉选择用, 全部经 sing-geosite/sing-geoip 验证存在)
BUILTIN_RULESETS = [
    {"id": "geosite:openai", "label": "OpenAI / ChatGPT", "category": "AI"},
    {"id": "geosite:anthropic", "label": "Anthropic / Claude", "category": "AI"},
    {"id": "geosite:deepseek", "label": "DeepSeek", "category": "AI"},
    {"id": "geosite:xai", "label": "xAI / Grok", "category": "AI"},
    {"id": "geosite:perplexity", "label": "Perplexity", "category": "AI"},
    {"id": "geosite:google", "label": "Google 全家桶", "category": "Google"},
    {"id": "geosite:youtube", "label": "YouTube", "category": "视频"},
    {"id": "geosite:netflix", "label": "Netflix", "category": "视频"},
    {"id": "geosite:disney", "label": "Disney+", "category": "视频"},
    {"id": "geosite:twitch", "label": "Twitch", "category": "视频"},
    {"id": "geosite:telegram", "label": "Telegram", "category": "社交"},
    {"id": "geosite:tiktok", "label": "TikTok", "category": "社交"},
    {"id": "geosite:twitter", "label": "Twitter / X", "category": "社交"},
    {"id": "geosite:instagram", "label": "Instagram", "category": "社交"},
    {"id": "geosite:facebook", "label": "Facebook", "category": "社交"},
    {"id": "geosite:discord", "label": "Discord", "category": "社交"},
    {"id": "geosite:github", "label": "GitHub", "category": "开发"},
    {"id": "geosite:binance", "label": "Binance", "category": "Crypto"},
    {"id": "geosite:bybit", "label": "Bybit", "category": "Crypto"},
    {"id": "geosite:apple", "label": "Apple", "category": "其他"},
    {"id": "geosite:microsoft", "label": "Microsoft", "category": "其他"},
    {"id": "geosite:amazon", "label": "Amazon", "category": "其他"},
    {"id": "geosite:reddit", "label": "Reddit", "category": "其他"},
    {"id": "geosite:spotify", "label": "Spotify", "category": "其他"},
    {"id": "geosite:steam", "label": "Steam", "category": "其他"},
    {"id": "geoip:cn", "label": "中国 IP", "category": "IP段"},
    {"id": "geoip:us", "label": "美国 IP", "category": "IP段"},
    {"id": "geoip:hk", "label": "香港 IP", "category": "IP段"},
    {"id": "geoip:tw", "label": "台湾 IP", "category": "IP段"},
    {"id": "geoip:jp", "label": "日本 IP", "category": "IP段"},
    {"id": "geoip:sg", "label": "新加坡 IP", "category": "IP段"},
    {"id": "geoip:kr", "label": "韩国 IP", "category": "IP段"},
    {"id": "geoip:de", "label": "德国 IP", "category": "IP段"},
]

def _expand_ruleset_shorthand(url):
    """展开规则集简写: geosite:binance / geoip:us -> 完整 SRS 地址 (走 ghfast 镜像)"""
    u = url.strip()
    low = u.lower()
    if low.startswith("geosite:") and "://" not in u:
        name = u.split(":", 1)[1].strip().lower()
        if name:
            return f"https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{name}.srs"
    elif low.startswith("geoip:") and "://" not in u:
        name = u.split(":", 1)[1].strip().lower()
        if name:
            return f"https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{name}.srs"
    return u

def _ensure_user_ruleset(url):
    """下载用户规则集(srs)到 data/rulesets/, 返回 rule_set tag; 失败返回 None"""
    url = _expand_ruleset_shorthand(url)
    import hashlib
    try:
        d = hashlib.md5(url.encode()).hexdigest()[:12]
        tag = f"user-{d}"
        dest_dir = os.path.join(DATA_DIR, "rulesets")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, f"{tag}.srs")
        if not os.path.exists(dest) or os.path.getsize(dest) == 0:
            req = urllib.request.Request(url, headers={"User-Agent": "singbox-ui/2.0"})
            with urllib.request.urlopen(req, timeout=30) as r, open(dest, "wb") as f:
                f.write(r.read())
            append_log(f"规则集已下载: {tag} <- {url[:60]}")
        return tag
    except Exception as e:
        append_log(f"规则集下载失败: {url[:60]} ({e})")
        return None

def build_config_with_preset(valid_external_nodes: list):
    """v2: 最小化构建 - 节点 + 内建5组 + DIY分组, 选择从 selections.json 恢复"""
    groups = load_groups()["groups"]
    selections = load_selections()
    settings = load_settings()

    seen, dedup_nodes, node_tags = set(), [], []
    blocked_cnt = 0
    for ob in valid_external_nodes:
        tag = str(ob.get("tag", "")).strip()
        if not tag:
            continue
        if _is_blocked_node_tag(tag):
            blocked_cnt += 1
            continue
        base, idx = tag, 2
        while tag in seen:
            tag = f"{base}-{idx}"
            idx += 1
        if tag != ob.get("tag"):
            ob = dict(ob)  # 仅 tag 重名时才拷贝, 99% 情况零拷贝
            ob["tag"] = tag
        seen.add(tag)
        node_tags.append(tag)
        dedup_nodes.append(ob)
    if blocked_cnt:
        append_log(f"已过滤 {blocked_cnt} 个信息节点(官网/流量/套餐/到期等)")

    # 按地区归类 (仅含非空地区)
    region_list = classify_nodes_by_region(dedup_nodes)  # [(地区名, [tags])]
    region_auto_tags = [f"{r}自动" for r, _ in region_list]
    region_manual_tags = [f"{r}手动" for r, _ in region_list]

    cfg = _v2_base_config()
    outbounds = []
    outbounds.extend(dedup_nodes)
    outbounds.append({"type": "direct", "tag": "直连"})
    outbounds.append(_v2_selector("手动选择", node_tags or ["直连"], selections.get("手动选择")))
    outbounds.append({
        "type": "urltest", "tag": "自动选择",
        "outbounds": node_tags or ["直连"],
        "url": "http://www.gstatic.com/generate_204",
        "interval": "3m", "tolerance": 50,
    })
    # 各地区自动/手动组
    for r_name, r_tags in region_list:
        outbounds.append({
            "type": "urltest", "tag": f"{r_name}自动",
            "outbounds": r_tags,
            "url": "http://www.gstatic.com/generate_204",
            "interval": "5m", "tolerance": 50,
        })
        outbounds.append(_v2_selector(f"{r_name}手动", r_tags, selections.get(f"{r_name}手动")))
    proxy_members = ["自动选择", "手动选择"] + region_auto_tags + region_manual_tags + ["直连"]
    outbounds.append(_v2_selector("默认代理", proxy_members,
                                  selections.get("默认代理", "自动选择")))
    diy_names = []
    diy_members = ["默认代理", "自动选择", "手动选择"] + region_auto_tags + region_manual_tags + ["直连"]
    for g in groups:
        name = str(g.get("name", "")).strip()
        if not name or name in ("直连", "默认代理", "自动选择", "手动选择", "漏网之鱼") \
                or name in region_auto_tags or name in region_manual_tags:
            continue
        diy_names.append(name)
        outbounds.append(_v2_selector(name, diy_members, selections.get(name, "默认代理")))
    outbounds.append(_v2_selector("漏网之鱼", ["默认代理", "直连"],
                                  selections.get("漏网之鱼", "默认代理")))
    cfg["outbounds"] = outbounds

    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"inbound": ["dns-in"], "action": "hijack-dns", "protocol": "dns"},
        {"ip_is_private": True, "outbound": "直连"},
    ]
    for g in groups:
        name = str(g.get("name", "")).strip()
        if name not in diy_names:
            continue
        if g.get("domains"):
            rules.append({"domain": list(dict.fromkeys(g["domains"])), "outbound": name})
        if g.get("domain_suffix"):
            rules.append({"domain_suffix": list(dict.fromkeys(g["domain_suffix"])), "outbound": name})
        if g.get("keywords"):
            rules.append({"domain_keyword": list(dict.fromkeys(g["keywords"])), "outbound": name})
        if g.get("ip_cidr"):
            rules.append({"ip_cidr": list(dict.fromkeys(g["ip_cidr"])), "outbound": name})
        for url in g.get("ruleset_urls", []) or []:
            tag = _ensure_user_ruleset(str(url).strip())
            if tag:
                # 注册到 rule_set
                rs_list = cfg["route"].setdefault("rule_set", [])
                if not any(r.get("tag") == tag for r in rs_list):
                    rs_list.append({"tag": tag, "type": "local", "format": "binary",
                                    "path": os.path.join(DATA_DIR, "rulesets", f"{tag}.srs")})
                rules.append({"rule_set": [tag], "outbound": name})
    rules.append({"domain_suffix": CN_DOMAIN_SUFFIXES, "outbound": "直连"})
    rules.append({"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "直连"})
    if settings.get("quic_block", True):
        rules.append({"network": "udp", "port": 443, "action": "reject"})
    cfg["route"]["rules"] = rules
    return sanitize_singbox_dict(cfg), len(node_tags)

def capture_live_selections():
    """从 clash API 读取各 selector 当前选择, 存入 selections.json (重建配置前调用)"""
    try:
        controller, secret = manager.get_clash_api_config()
        if not (manager.is_running() and controller):
            return
        url = f"{controller}/proxies"
        req = urllib.request.Request(url)
        if secret:
            req.add_header("Authorization", f"Bearer {secret}")
        with DIRECT_OPENER.open(req, timeout=5) as resp:
            data = json.load(resp)
        sel = load_selections()
        for name, p in data.get("proxies", {}).items():
            if p.get("type") == "Selector" and p.get("now"):
                sel[name] = p["now"]
        save_selections(sel)
        append_log(f"已捕获 {len(sel)} 个策略组选择状态")
    except Exception as e:
        append_log(f"捕获选择状态失败: {e}")

def rebuild_and_restart(reason="配置重建"):
    """用 data/nodes.json + groups/selections/settings 重建配置并重启"""
    capture_live_selections()
    nodes = load_nodes()
    cfg, _ = build_config_with_preset(nodes)
    cfg_str = json.dumps(cfg, indent=2, ensure_ascii=False)
    if os.path.exists(CONFIG_PATH):
        shutil.copy(CONFIG_PATH, os.path.join(DATA_DIR, "config.json.bak"))
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(cfg_str)
    append_log(f"{reason}: 已重建配置 (节点 {len(nodes)} 个)")
    return manager.restart()


class SingBoxManager:
    def __init__(self):
        self.process = None
        self.start_time = None
        self.bin_path = self._find_binary()
        self._log_thread = None

    def _find_binary(self):
        local_bin = os.path.join(BIN_DIR, "sing-box" + (".exe" if os.name == "nt" else ""))
        if os.path.exists(local_bin) and os.access(local_bin, os.X_OK | os.F_OK):
            return local_bin
        sys_bin = shutil.which("sing-box")
        if sys_bin:
            return sys_bin
        return local_bin

    def get_arch(self):
        m = platform.machine().lower()
        if m in ["x86_64", "amd64"]:
            return "amd64"
        elif m in ["aarch64", "arm64"]:
            return "arm64"
        elif "armv7" in m or m == "arm":
            return "armv7"
        elif m in ["i386", "i686"]:
            return "386"
        return m

    def check_version(self):
        self.bin_path = self._find_binary()
        if not os.path.exists(self.bin_path):
            return "未安装内核"
        try:
            res = subprocess.run([self.bin_path, "version"], capture_output=True, text=True, timeout=3)
            first_line = res.stdout.strip().split("\n")[0]
            return first_line if first_line else "未知版本"
        except Exception as e:
            return f"检测失败: {e}"

    def is_running(self):
        if self.process is None:
            return False
        return self.process.poll() is None

    def get_status(self):
        running = self.is_running()
        uptime_sec = int(time.time() - self.start_time) if (running and self.start_time) else 0
        hours, rem = divmod(uptime_sec, 3600)
        minutes, seconds = divmod(rem, 60)
        uptime_str = f"{hours}h {minutes}m {seconds}s" if running else "未运行"

        memory_usage = "N/A"
        if running and os.name != "nt":
            try:
                pid = self.process.pid
                statm_path = f"/proc/{pid}/statm"
                if os.path.exists(statm_path):
                    with open(statm_path, "r") as f:
                        parts = f.read().split()
                        rss_pages = int(parts[1])
                        page_size_kb = os.sysconf("SC_PAGE_SIZE") // 1024
                        memory_usage = f"{(rss_pages * page_size_kb) / 1024:.1f} MB"
            except Exception:
                pass

        return {
            "running": running,
            "pid": self.process.pid if running else None,
            "uptime": uptime_str,
            "memory": memory_usage,
            "arch": self.get_arch(),
            "kernel_version": self.check_version(),
            "bin_path": self.bin_path,
            "config_exists": os.path.exists(CONFIG_PATH)
        }

    def validate_config(self, config_content: str):
        try:
            json.loads(config_content)
        except Exception as e:
            return False, f"JSON 语法错误: {e}"

        self.bin_path = self._find_binary()
        if os.path.exists(self.bin_path):
            temp_file = os.path.join(DATA_DIR, "temp_check.json")
            try:
                with open(temp_file, "w", encoding="utf-8") as f:
                    f.write(config_content)
                res = subprocess.run([self.bin_path, "check", "-c", temp_file], capture_output=True, text=True, timeout=5)
                if res.returncode != 0:
                    err = (res.stderr or res.stdout).strip()
                    return False, f"Sing-Box 校验未通过:\n{err}"
            except Exception:
                pass
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
        return True, "校验通过"

    def _spawn_process(self):
        cmd = [self.bin_path, "run", "-c", CONFIG_PATH]
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        self.start_time = time.time()

        def log_reader(proc):
            try:
                for line in proc.stdout:
                    l = line.strip()
                    if l:
                        append_log(l)
            except Exception:
                pass

        self._log_thread = threading.Thread(target=log_reader, args=(self.process,), daemon=True)
        self._log_thread.start()
        time.sleep(0.45)
        if self.process.poll() is None:
            setup_gateway_network()
            if verify_gateway_diversion():
                append_log("旁路由分流链路自检通过: table 2022 默认路由已指向 tun0")
            else:
                append_log("警告: table 2022 中没有 tun0 默认路由, 旁路由分流未生效! "
                           "请检查: 1) sing-box 日志中 TUN 是否启动成功 "
                           "2) /dev/net/tun 是否可用 3) config.json 是否包含 tun-in")
            return True
        return False

    def start(self):
        if self.is_running():
            return True, "服务已在运行中"

        self.bin_path = self._find_binary()
        if not os.path.exists(self.bin_path):
            return False, f"未找到 sing-box 核心程序: {self.bin_path}，请先点击安装核心"

        if not os.path.exists(CONFIG_PATH):
            # v2: 用保存的节点快照重建最小化配置 (无节点时为空配置, 仅直连)
            preset_data, _ = build_config_with_preset(load_nodes())
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(preset_data, f, indent=2, ensure_ascii=False)
            append_log("已按 v2 最小化模型重建 config.json")

        setup_gateway_network()
        clear_stale_cache_files()
        sanitize_config_file(CONFIG_PATH)

        try:
            chk = subprocess.run([self.bin_path, "check", "-c", CONFIG_PATH], capture_output=True, text=True, timeout=5)
            if chk.returncode != 0:
                err_detail = (chk.stderr or chk.stdout).strip()
                append_log(f"配置预检未通过: {err_detail}")
                return False, f"配置校验失败: {err_detail}"
        except Exception:
            pass

        try:
            if self._spawn_process():
                append_log(f"Sing-Box 核心已启动 (PID: {self.process.pid}，已启用 DoH 防回环、53 端口 DNS 接管与旁路由分流)")
                return True, "启动成功"

            recent_logs = "\n".join(list(LOG_BUFFER)[-6:])
            if "tun" in recent_logs.lower() or "/dev/net/tun" in recent_logs.lower():
                append_log("检测到当前容器环境不支持创建 TUN 虚拟网卡，正在自动切换为 Mixed (0.0.0.0:2080) 模式重试启动...")
                sanitize_config_file(CONFIG_PATH, force_disable_tun=True)
                if self._spawn_process():
                    append_log(f"Sing-Box 核心已通过 Mixed 代理模式成功启动 (PID: {self.process.pid}，端口: 2080)")
                    return True, "启动成功 (当前容器未开启 TUN 设备，已自动降级为 Mixed 端口 2080 模式)"

            self.process = None
            self.start_time = None
            append_log("Sing-Box 启动后立即退出，请检查日志。")
            return False, f"启动失败，内核已退出:\n{recent_logs}"
        except Exception as e:
            append_log(f"启动失败: {e}")
            return False, f"启动异常: {e}"

    def stop(self):
        if not self.is_running():
            return True, "服务当前未运行"

        try:
            pid = self.process.pid
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
            append_log(f"Sing-Box 核心已停止 (原 PID: {pid})")
            self.process = None
            self.start_time = None
            return True, "已成功停止"
        except Exception as e:
            return False, f"停止失败: {e}"

    def restart(self):
        self.stop()
        time.sleep(0.4)
        return self.start()

    def download_kernel(self, custom_url=None):
        arch = self.get_arch()
        version = "1.14.3"
        if not custom_url:
            url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}.tar.gz"
        else:
            url = custom_url

        append_log(f"开始准备下载 sing-box 内核 ({arch})...")
        tar_path = os.path.join(DATA_DIR, f"sing-box-{arch}.tar.gz")

        candidate_urls = [url]
        if not custom_url:
            candidate_urls = [
                f"https://ghfast.top/{url}",
                f"https://ghproxy.net/{url}",
                url
            ]

        download_success = False
        last_error = ""

        for dl_url in candidate_urls:
            try:
                append_log(f"尝试下载链接: {dl_url}")
                req = urllib.request.Request(
                    dl_url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; SingBoxDashboard/1.0)"}
                )
                with DIRECT_OPENER.open(req, timeout=25) as resp, open(tar_path, "wb") as f:
                    shutil.copyfileobj(resp, f)
                download_success = True
                break
            except Exception as e:
                last_error = str(e)
                append_log("此节点下载失败或超时，自动切换下一镜像...")

        if not download_success:
            return False, f"下载内核失败 (所有镜像源均超时): {last_error}"

        try:
            append_log("下载完成，正在解压内核...")
            with tarfile.open(tar_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("sing-box") or member.name == "sing-box":
                        f_in = tar.extractfile(member)
                        target_bin = os.path.join(BIN_DIR, "sing-box")
                        with open(target_bin, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                        os.chmod(target_bin, 0o755)
                        break

            if os.path.exists(tar_path):
                os.remove(tar_path)

            self.bin_path = self._find_binary()
            ver = self.check_version()
            append_log(f"内核安装成功！当前版本: {ver}")
            return True, f"内核安装成功: {ver}"
        except Exception as e:
            err = f"解压失败: {e}"
            append_log(err)
            return False, err

    def get_clash_api_config(self):
        try:
            data = _get_effective_config_dict()
            clash_api = data.get("experimental", {}).get("clash_api", {})
            controller = str(clash_api.get("external_controller", "127.0.0.1:9090")).strip()
            secret = str(clash_api.get("secret", "")).strip()
            if not controller.startswith("http"):
                controller = f"http://{controller}"
            parsed = urllib.parse.urlsplit(controller)
            host = parsed.hostname or "127.0.0.1"
            if host in ("0.0.0.0", "::", ""):
                host = "127.0.0.1"
            port = parsed.port or 9090
            return f"{parsed.scheme}://{host}:{port}", secret
        except Exception:
            return "http://127.0.0.1:9090", ""

    def get_proxies_data(self):
        controller, secret = self.get_clash_api_config()
        if self.is_running() and controller:
            try:
                req = urllib.request.Request(f"{controller}/proxies")
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with DIRECT_OPENER.open(req, timeout=2.0) as resp:
                    clash_data = json.loads(resp.read().decode("utf-8"))
                    proxies = clash_data.get("proxies", {})
                    groups = []
                    nodes_info = {}

                    for name, item in proxies.items():
                        ptype = str(item.get("type", "")).lower()
                        if ptype in ["selector", "urltest", "fallback", "loadbalance"]:
                            if name == "GLOBAL":
                                continue
                            groups.append({
                                "name": name,
                                "type": item.get("type", "Selector"),
                                "now": item.get("now", ""),
                                "all": item.get("all", [])
                            })
                        else:
                            delay = 0
                            history = item.get("history", [])
                            if history:
                                delay = history[-1].get("delay", 0)
                            nodes_info[name] = {
                                "type": item.get("type", "Proxy"),
                                "delay": delay
                            }

                    if groups:
                        return {"source": "clash_api", "groups": groups, "nodes": nodes_info}
            except Exception:
                pass

        if not os.path.exists(CONFIG_PATH):
            return {"source": "none", "groups": [], "nodes": {}}

        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            data = sanitize_singbox_dict(data)

            outbounds = data.get("outbounds", [])
            groups = []
            nodes_info = {}

            for ob in outbounds:
                tag = ob.get("tag", "")
                ob_type = ob.get("type", "")
                if ob_type in ["selector", "urltest"]:
                    all_nodes = ob.get("outbounds", [])
                    default_now = ob.get("default", all_nodes[0] if all_nodes else "")
                    groups.append({
                        "name": tag,
                        "type": "Selector" if ob_type == "selector" else "URLTest",
                        "now": default_now,
                        "all": all_nodes
                    })
                elif ob_type not in ["direct", "block", "dns"]:
                    nodes_info[tag] = {
                        "type": ob_type,
                        "delay": 0
                    }

            return {"source": "config_file", "groups": groups, "nodes": nodes_info}
        except Exception as e:
            return {"source": "error", "message": str(e), "groups": [], "nodes": {}}

    def select_proxy(self, group_name: str, node_name: str):
        controller, secret = self.get_clash_api_config()
        switched_live = False

        if self.is_running() and controller:
            try:
                put_url = f"{controller}/proxies/{urllib.parse.quote(group_name, safe='')}"
                put_data = json.dumps({"name": node_name}).encode("utf-8")
                req = urllib.request.Request(put_url, data=put_data, method="PUT")
                req.add_header("Content-Type", "application/json")
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with DIRECT_OPENER.open(req, timeout=2.5) as resp:
                    if resp.status in [200, 204]:
                        switched_live = True
                        append_log(f"已动态切换出站组 [{group_name}] -> {node_name}")
            except Exception as e:
                append_log(f"动态切换尝试未生效 ({e})，将持久化保存配置")

        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                updated = False
                for ob in cfg.get("outbounds", []):
                    if ob.get("tag") == group_name and ob.get("type") == "selector":
                        ob["default"] = node_name
                        updated = True
                        break
                if updated:
                    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception as e:
                append_log(f"持久化默认节点失败: {e}")

        msg = f"节点已成功切换至: {node_name}"
        if not switched_live and self.is_running():
            msg += " (当前组为自动测速组或需重启生效)"
        return True, msg

    def test_delay(self, node_name: str):
        controller, secret = self.get_clash_api_config()
        if not (self.is_running() and controller):
            return False, "需先启动 Sing-Box 核心方可进行在线测速"

        encoded_node = urllib.parse.quote(node_name, safe="")
        test_urls = [
            "http://www.gstatic.com/generate_204",
            "http://cp.cloudflare.com/generate_204"
        ]

        for t_url in test_urls:
            try:
                q_url = urllib.parse.quote(t_url, safe="")
                url = f"{controller}/proxies/{encoded_node}/delay?timeout=5000&url={q_url}"
                req = urllib.request.Request(url)
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with DIRECT_OPENER.open(req, timeout=6.0) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    delay_val = res.get("delay", 0)
                    if delay_val > 0:
                        return True, delay_val
            except urllib.error.HTTPError as he:
                if he.code == 404:
                    return False, "节点未注册"
                continue
            except Exception:
                continue

        return False, "超时/失败"

manager = SingBoxManager()

class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body_json(self):
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            return {}
        body = self.rfile.read(content_len).decode("utf-8")
        return json.loads(body)

    def do_GET(self):
        try:
            if self.path == "/api/status":
                self._send_json(manager.get_status())
            elif self.path == "/api/logs":
                self._send_json(list(LOG_BUFFER))
            elif self.path == "/api/config":
                if os.path.exists(CONFIG_PATH):
                    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                        content = f.read()
                else:
                    content = json.dumps(load_preset_dict(), indent=2, ensure_ascii=False)
                self._send_json({"config": content})
            elif self.path == "/api/preset":
                content = json.dumps(load_preset_dict(), indent=2, ensure_ascii=False)
                self._send_json({"preset": content})
            elif self.path == "/api/subscriptions":
                self._send_json(_load_subscriptions())
            elif self.path == "/api/groups":
                self._send_json(load_groups())
            elif self.path == "/api/selections":
                self._send_json({"selections": load_selections()})
            elif self.path == "/api/rulesets/builtin":
                self._send_json({"rulesets": BUILTIN_RULESETS})
            elif self.path == "/api/settings":
                self._send_json(load_settings())
            elif self.path in ["/api/proxies", "/api/nodes"]:
                self._send_json(manager.get_proxies_data())
            elif self.path.startswith("/api/nodes/delay"):
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)
                node = params.get("node", [""])[0]
                if not node:
                    self._send_json({"success": False, "message": "参数 node 不能为空"})
                    return
                ok, val = manager.test_delay(node)
                if ok:
                    self._send_json({"success": True, "delay": val})
                else:
                    self._send_json({"success": False, "message": val})
            else:
                super().do_GET()
        except Exception as e:
            append_log(f"GET 异常: {e}")
            self._send_json({"success": False, "error": str(e), "message": str(e)})

    def do_POST(self):
        try:
            if self.path == "/api/service/start":
                ok, msg = manager.start()
                self._send_json({"success": ok, "message": msg})
            elif self.path == "/api/service/stop":
                ok, msg = manager.stop()
                self._send_json({"success": ok, "message": msg})
            elif self.path == "/api/service/restart":
                ok, msg = manager.restart()
                self._send_json({"success": ok, "message": msg})
            elif self.path == "/api/config/save":
                data = self._read_body_json()
                config_str = data.get("config", "")
                parsed_cfg = json.loads(config_str)
                sanitized_cfg = sanitize_singbox_dict(parsed_cfg)
                config_str = json.dumps(sanitized_cfg, indent=2, ensure_ascii=False)

                validate = data.get("validate", True)
                if validate:
                    ok, msg = manager.validate_config(config_str)
                    if not ok:
                        append_log(f"保存校验未通过: {msg}")
                        self._send_json({"success": False, "message": msg})
                        return

                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    f.write(config_str)
                append_log("配置文件已保存并自动完成 1.14 兼容性修复")
                self._send_json({"success": True, "message": "配置保存成功", "config": config_str})

            elif self.path == "/api/nodes/select":
                data = self._read_body_json()
                group = data.get("group", "")
                node = data.get("node", "")
                if not group or not node:
                    self._send_json({"success": False, "message": "group 和 node 不能为空"})
                    return
                ok, msg = manager.select_proxy(group, node)
                self._send_json({"success": ok, "message": msg})

            elif self.path == "/api/groups":
                data = self._read_body_json()
                groups = load_groups()["groups"]
                name = str(data.get("name", "")).strip()
                if not name:
                    self._send_json({"success": False, "message": "分组名称不能为空"})
                    return
                if any(g.get("name") == name for g in groups):
                    self._send_json({"success": False, "message": "分组名称已存在"})
                    return
                g = {
                    "id": new_group_id(), "name": name, "order": len(groups),
                    "domains": [s.strip() for s in data.get("domains", []) if str(s).strip()],
                    "domain_suffix": [s.strip() for s in data.get("domain_suffix", []) if str(s).strip()],
                    "keywords": [s.strip() for s in data.get("keywords", []) if str(s).strip()],
                    "ip_cidr": [s.strip() for s in data.get("ip_cidr", []) if str(s).strip()],
                    "ruleset_urls": [s.strip() for s in data.get("ruleset_urls", []) if str(s).strip()],
                }
                groups.append(g)
                save_groups(groups)
                ok, msg = rebuild_and_restart(f"新建分组 [{name}]")
                self._send_json({"success": ok, "message": msg, "group": g})
            elif self.path == "/api/groups/reorder":
                data = self._read_body_json()
                ids = data.get("ids", [])
                groups = load_groups()["groups"]
                by_id = {g.get("id"): g for g in groups}
                ordered = [by_id[i] for i in ids if i in by_id]
                ordered += [g for g in groups if g.get("id") not in set(ids)]
                save_groups(ordered)
                ok, msg = rebuild_and_restart("分组排序已更新")
                self._send_json({"success": ok, "message": msg})
            elif self.path.startswith("/api/groups/") and self.path.count("/") == 3:
                gid = self.path.rsplit("/", 1)[1]
                groups = load_groups()["groups"]
                g = next((x for x in groups if x.get("id") == gid), None)
                if g is None:
                    self._send_json({"success": False, "message": "分组不存在"})
                    return
                data = self._read_body_json()
                if data.get("_delete"):
                    groups = [x for x in groups if x.get("id") != gid]
                    save_groups(groups)
                    ok, msg = rebuild_and_restart(f"删除分组 [{g.get('name')}]")
                    self._send_json({"success": ok, "message": msg})
                    return
                for k in ("domains", "domain_suffix", "keywords", "ip_cidr", "ruleset_urls"):
                    if k in data:
                        g[k] = [str(s).strip() for s in data[k] if str(s).strip()]
                if data.get("name"):
                    g["name"] = str(data["name"]).strip()
                save_groups(groups)
                ok, msg = rebuild_and_restart(f"更新分组 [{g.get('name')}]")
                self._send_json({"success": ok, "message": msg, "group": g})
                return
            elif self.path == "/api/settings":
                data = self._read_body_json()
                s = load_settings()
                if "quic_block" in data:
                    s["quic_block"] = bool(data["quic_block"])
                save_settings(s)
                ok, msg = rebuild_and_restart("设置已更新")
                self._send_json({"success": ok, "message": msg, "settings": s})
            elif self.path == "/api/subscribe/import":
                data = self._read_body_json()
                sub_url = data.get("url", "").strip()
                use_preset = data.get("use_preset", True)

                if not sub_url:
                    self._send_json({"success": False, "message": "订阅链接或节点内容不能为空"})
                    return

                if re.match(r"^https?://", sub_url, re.I):
                    append_log(f"正在拉取远程订阅: {sub_url}")
                    full_cfg, valid_external, err_msg = fetch_and_parse_subscription(sub_url)
                    if err_msg and not valid_external and not full_cfg:
                        msg = f"拉取或解析远程订阅失败: {err_msg}"
                        append_log(msg)
                        self._send_json({"success": False, "message": msg})
                        return
                else:
                    append_log("正在解析直接粘贴的节点链接/订阅文本...")
                    full_cfg, valid_external = parse_subscription_payload(sub_url)

                if not valid_external and not full_cfg:
                    msg = "未能从订阅中提取到有效节点（支持 Sub-Store 链接、Sing-Box JSON、Base64/明文 anytls/vless/hy2 链接、Clash YAML）"
                    append_log(msg)
                    self._send_json({"success": False, "message": msg})
                    return

                if use_preset or not full_cfg:
                    final_config, _node_count = build_config_with_preset(valid_external)
                else:
                    final_config = sanitize_singbox_dict(full_cfg)
                    _node_count = len(valid_external or [])

                final_config_str = json.dumps(final_config, indent=2, ensure_ascii=False)

                if os.path.exists(CONFIG_PATH):
                    shutil.copy(CONFIG_PATH, os.path.join(DATA_DIR, "config.json.bak"))
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    f.write(final_config_str)

                anytls_count = sum(1 for n in valid_external if n.get("type") == "anytls")
                extra_info = f"（含 {anytls_count} 个 AnyTLS 节点）" if anytls_count else ""
                append_log(f"订阅更新成功！共提取 {_node_count} 个节点{extra_info}并注入分流策略组。")
                ok, restart_msg = manager.restart()
                status_note = "核心已启动生效" if ok else f"但启动异常: {restart_msg}"
                # 同步记入订阅仓库, 供"多订阅管理"列表展示与一键切换
                try:
                    _store = _load_subscriptions()
                    _rec = next((s for s in _store["subscriptions"] if s.get("url") == sub_url), None)
                    if _rec is None:
                        _rec = {"id": _new_sub_id(),
                                "name": f"订阅 {len(_store['subscriptions']) + 1}",
                                "url": sub_url, "use_preset": bool(use_preset)}
                        _store["subscriptions"].append(_rec)
                    _rec["node_count"] = _node_count
                    _rec["anytls_count"] = anytls_count
                    _rec["updated_at"] = _now_str()
                    if ok:
                        _store["active_id"] = _rec["id"]
                    _save_subscriptions(_store)
                except Exception as _e:
                    append_log(f"订阅记录入库失败: {_e}")
                self._send_json({
                    "success": ok,
                    "message": f"订阅更新成功！已载入 {len(valid_external)} 个节点{extra_info}，{status_note}。",
                    "config": final_config_str
                })

            elif self.path == "/api/subscriptions/add":
                data = self._read_body_json()
                name = (data.get("name") or "").strip()
                url = (data.get("url") or "").strip()
                use_preset = data.get("use_preset", True)
                apply_now = data.get("apply_now", False)
                if not url:
                    self._send_json({"success": False, "message": "订阅链接或节点内容不能为空"})
                    return
                full_cfg, valid_external, err_msg = _parse_subscription_input(url)
                if _subscription_parse_failed(full_cfg, valid_external, err_msg):
                    msg = (f"拉取或解析订阅失败: {err_msg}"
                           if err_msg else "未能从订阅中提取到有效节点（支持 Sub-Store 链接、Sing-Box JSON、Base64/明文 anytls/vless/hy2 链接、Clash YAML）")
                    append_log(msg)
                    self._send_json({"success": False, "message": msg})
                    return
                store = _load_subscriptions()
                rec = next((s for s in store["subscriptions"] if s.get("url") == url), None)
                if rec is None:
                    rec = {"id": _new_sub_id(),
                           "name": name or f"订阅 {len(store['subscriptions']) + 1}",
                           "url": url, "use_preset": bool(use_preset)}
                    store["subscriptions"].append(rec)
                else:
                    if name:
                        rec["name"] = name
                    rec["use_preset"] = bool(use_preset)
                rec["node_count"] = len(valid_external)
                rec["anytls_count"] = sum(1 for n in valid_external if n.get("type") == "anytls")
                rec["updated_at"] = _now_str()
                config_str = ""
                if apply_now:
                    ok, msg, config_str = _apply_subscription_record(
                        rec, preparsed=(full_cfg, valid_external))
                    if ok:
                        store["active_id"] = rec["id"]
                    _save_subscriptions(store)
                    self._send_json({"success": ok, "message": msg, "data": store,
                                     "config": config_str})
                else:
                    _save_subscriptions(store)
                    self._send_json({"success": True,
                                     "message": f"订阅「{rec['name']}」已保存（{len(valid_external)} 个节点），点击「⚡ 立即切换生效」可应用。",
                                     "data": store})
                return

            elif self.path == "/api/subscriptions/select":
                data = self._read_body_json()
                sub_id = str(data.get("id", ""))
                store = _load_subscriptions()
                rec = next((s for s in store["subscriptions"] if str(s.get("id")) == sub_id), None)
                if not rec:
                    self._send_json({"success": False, "message": "未找到该订阅记录，请刷新页面重试"})
                    return
                ok, msg, config_str = _apply_subscription_record(rec)
                if ok:
                    store["active_id"] = rec["id"]
                _save_subscriptions(store)
                self._send_json({"success": ok, "message": msg, "data": store,
                                 "config": config_str})
                return

            elif self.path == "/api/subscriptions/update":
                data = self._read_body_json()
                sub_id = str(data.get("id", ""))
                store = _load_subscriptions()
                rec = next((s for s in store["subscriptions"] if str(s.get("id")) == sub_id), None)
                if not rec:
                    self._send_json({"success": False, "message": "未找到该订阅记录，请刷新页面重试"})
                    return
                if str(store.get("active_id")) == sub_id:
                    ok, msg, config_str = _apply_subscription_record(rec)
                else:
                    full_cfg, valid_external, err_msg = _parse_subscription_input(rec.get("url", ""))
                    if _subscription_parse_failed(full_cfg, valid_external, err_msg):
                        msg = f"刷新失败: {err_msg or '未能提取到有效节点'}"
                        append_log(msg)
                        self._send_json({"success": False, "message": msg})
                        return
                    rec["node_count"] = len(valid_external)
                    rec["anytls_count"] = sum(1 for n in valid_external if n.get("type") == "anytls")
                    rec["updated_at"] = _now_str()
                    ok, msg, config_str = True, f"订阅「{rec.get('name')}」已刷新：{len(valid_external)} 个节点。", ""
                    append_log(msg)
                _save_subscriptions(store)
                self._send_json({"success": ok, "message": msg, "data": store,
                                 "config": config_str})
                return

            elif self.path == "/api/subscriptions/delete":
                data = self._read_body_json()
                sub_id = str(data.get("id", ""))
                store = _load_subscriptions()
                before = len(store["subscriptions"])
                store["subscriptions"] = [s for s in store["subscriptions"]
                                          if str(s.get("id")) != sub_id]
                if str(store.get("active_id")) == sub_id:
                    store["active_id"] = ""
                _save_subscriptions(store)
                if len(store["subscriptions"]) == before:
                    self._send_json({"success": False, "message": "未找到该订阅记录"})
                else:
                    append_log(f"订阅记录已删除 (id={sub_id})")
                    self._send_json({"success": True, "message": "订阅记录已删除", "data": store})
                return

            elif self.path == "/api/system/clean_cache":
                try:
                    append_log("正在深度清理 sing-box 缓存并基于当前激活订阅重构配置...")
                    manager.stop()
                    time.sleep(0.5)
                    clear_stale_cache_files()
                    store = _load_subscriptions()
                    rec = next((s for s in store["subscriptions"]
                                if str(s.get("id")) == str(store.get("active_id"))), None)
                    config_str = ""
                    if rec and rec.get("url"):
                        ok, msg, config_str = _apply_subscription_record(rec)
                    else:
                        ok, start_msg = manager.start()
                        msg = ("缓存已清理，核心已重启（无激活订阅可重构）" if ok
                               else f"缓存已清理，但核心启动异常: {start_msg}")
                        append_log(msg)
                    _save_subscriptions(store)
                    self._send_json({"success": True, "message": msg, "data": store,
                                     "config": config_str})
                except Exception as e:
                    self._send_json({"success": False, "message": f"清理缓存失败: {e}"})
                return

            elif self.path == "/api/system/install_kernel":
                data = self._read_body_json()
                custom_url = data.get("url", None)
                ok, msg = manager.download_kernel(custom_url)
                self._send_json({"success": ok, "message": msg})
            else:
                self._send_json({"success": False, "error": "Not Found", "message": "接口不存在"}, 404)
        except Exception as e:
            err_trace = traceback.format_exc()
            append_log(f"POST 处理异常: {e}\n{err_trace}")
            self._send_json({"success": False, "message": f"处理失败: {e}"})

def run_server(port=9622):
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, "rulesets"), exist_ok=True)
    if os.path.exists(CONFIG_PATH):
        sanitize_config_file(CONFIG_PATH)

    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, DashboardHandler)
    httpd.daemon_threads = True
    append_log(f"Sing-Box WebUI 服务已启动 (多线程模式)，监听端口: {port}")
    print("=" * 60)
    print(" Sing-Box WebUI 仪表盘启动成功！")
    print(f" 监听地址: http://0.0.0.0:{port}")
    print(f" 本地访问: http://127.0.0.1:{port}")
    print(" 极简低功耗设计，适用平台: amd64 / arm64 / armv7 等")
    print("=" * 60)

    def auto_start_kernel():
        time.sleep(1)
        if not manager.is_running():
            ok, msg = manager.start()
            if ok:
                append_log(f"开箱自启机制: {msg}")
            else:
                append_log(f"开箱自启机制: 等待配置或内核安装 ({msg})")

    threading.Thread(target=auto_start_kernel, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止服务...")
        manager.stop()
        httpd.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sing-Box WebUI Dashboard")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 9622)), help="WebUI 端口 (默认 9622)")
    args = parser.parse_args()
    run_server(port=args.port)