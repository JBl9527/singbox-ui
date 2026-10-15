#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sing-Box WebUI Dashboard (v1.14.3 全特性适配版)
包含:
- 多线程并发测速 (ThreadingHTTPServer)
- 完整支持并标准化 AnyTLS / VLESS / Trojan / Shadowsocks / Hysteria2 等
- 智能多格式订阅解析 (Sing-Box JSON / Base64单节点链接 / Clash YAML)
- 1.14.3 自动化配置迁移与全维度 Sanitizer (移除旧DNS/Sniff/Block/DNS-out, 修复urltest default)
- TUN 死循环防御 (强制 auto_detect_interface) 与 Clash API safe URL 编码
"""

import os
import sys
import json
import time
import shutil
import base64
import tarfile
import urllib.request
import urllib.parse
import urllib.error
import platform
import subprocess
import threading
import argparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from collections import deque

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
PRESET_PATH = os.path.join(BASE_DIR, "templates", "preset_config.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")
BIN_DIR = os.path.join(BASE_DIR, "bin")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BIN_DIR, exist_ok=True)

# 内存日志缓冲队列（最多保存300条）
LOG_BUFFER = deque(maxlen=300)

def append_log(msg: str):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    LOG_BUFFER.append(f"[{timestamp}] {msg}")

# 官方支持的合法代理出站类型 (包含 AnyTLS)
VALID_PROXY_TYPES = {
    "anytls", "vless", "vmess", "shadowsocks", "trojan", "hysteria", "hysteria2",
    "tuic", "wireguard", "shadowtls", "tor", "ssh", "http", "socks"
}

# 绕过系统代理的直连 Opener (专门用于请求本地 Clash API 及直连测速)
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def classify_nodes_by_region(nodes):
    """根据节点 tag 智能归类地区"""
    regions = {
        "香港": {"keywords": ["hk", "hongkong", "hong kong", "香港", "🇭🇰"], "nodes": []},
        "日本": {"keywords": ["jp", "japan", "日本", "东京", "大阪", "🇯🇵"], "nodes": []},
        "狮城": {"keywords": ["sg", "singapore", "新加坡", "狮城", "🇸🇬"], "nodes": []},
        "美国": {"keywords": ["us", "united states", "america", "美国", "洛杉矶", "圣何塞", "硅谷", "西雅图", "纽约", "🇺🇸", "🇺🇲"], "nodes": []},
        "台湾": {"keywords": ["tw", "taiwan", "台湾", "台北", "🇹🇼"], "nodes": []},
    }
    for n in nodes:
        tag_lower = n.get("tag", "").lower()
        for r_name, r_data in regions.items():
            if any(k in tag_lower for k in r_data["keywords"]):
                r_data["nodes"].append(n["tag"])
                break
    return regions

def normalize_proxy_outbound(ob: dict) -> dict:
    """标准化代理节点结构，尤其是 anytls 与 clash 遗留字段"""
    if not isinstance(ob, dict):
        return ob
    otype = ob.get("type", "").lower()
    ob["type"] = otype

    # 标准化 server_port
    if "port" in ob and "server_port" not in ob:
        try:
            ob["server_port"] = int(ob.pop("port"))
        except Exception:
            pass

    # 处理 anytls 规范化
    if otype == "anytls":
        tls_cfg = ob.setdefault("tls", {})
        tls_cfg["enabled"] = True

        # 迁移顶层字段
        if "sni" in ob:
            tls_cfg["server_name"] = ob.pop("sni")
        elif "server_name" in ob:
            tls_cfg["server_name"] = ob.pop("server_name")
        elif "server" in ob and "server_name" not in tls_cfg:
            tls_cfg["server_name"] = ob["server"]

        if "skip-cert-verify" in ob:
            tls_cfg["insecure"] = bool(ob.pop("skip-cert-verify"))
        elif "insecure" in ob:
            tls_cfg["insecure"] = bool(ob.pop("insecure"))

        if "client-fingerprint" in ob:
            fp = ob.pop("client-fingerprint")
            tls_cfg.setdefault("utls", {})["enabled"] = True
            tls_cfg["utls"]["fingerprint"] = fp

        if "alpn" in ob:
            alpn = ob.pop("alpn")
            if isinstance(alpn, str):
                alpn = [x.strip() for x in alpn.split(",")]
            tls_cfg["alpn"] = alpn

        # 剔除 clash/其它多余字段
        for bad_k in ["udp", "tfo", "skip-cert-verify", "client-fingerprint", "sni"]:
            ob.pop(bad_k, None)

    return ob

def parse_node_uri(uri: str) -> dict:
    """解析单节点链接 (anytls://, vless://, ss:// 等)"""
    uri = uri.strip()
    if not uri or "://" not in uri:
        return None
    scheme, rest = uri.split("://", 1)
    scheme = scheme.lower()

    if scheme == "anytls":
        # anytls://password@server:port?sni=...#tag
        tag = ""
        if "#" in rest:
            rest, tag = rest.split("#", 1)
            tag = urllib.parse.unquote(tag)
        query_params = {}
        if "?" in rest:
            rest, q = rest.split("?", 1)
            query_params = urllib.parse.parse_qs(q)

        user_info, host_port = rest.split("@", 1) if "@" in rest else ("", rest)
        password = urllib.parse.unquote(user_info)
        host, port = host_port.split(":", 1) if ":" in host_port else (host_port, "443")
        
        sni = query_params.get("sni", query_params.get("peer", [host]))[0]
        insecure = query_params.get("insecure", query_params.get("allowInsecure", ["0"]))[0] in ["1", "true"]
        fp = query_params.get("fp", ["chrome"])[0]

        return normalize_proxy_outbound({
            "type": "anytls",
            "tag": tag or f"AnyTLS-{host}:{port}",
            "server": host,
            "server_port": int(port),
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": insecure,
                "utls": {"enabled": True, "fingerprint": fp}
            }
        })

    elif scheme in ["vless", "trojan", "hysteria2", "hy2"]:
        # 通用 URI 解析
        tag = ""
        if "#" in rest:
            rest, tag = rest.split("#", 1)
            tag = urllib.parse.unquote(tag)
        q_params = {}
        if "?" in rest:
            rest, q = rest.split("?", 1)
            q_params = urllib.parse.parse_qs(q)
        user_info, host_port = rest.split("@", 1) if "@" in rest else ("", rest)
        host, port = host_port.split(":", 1) if ":" in host_port else (host_port, "443")

        node_type = "hysteria2" if scheme in ["hysteria2", "hy2"] else scheme
        node = {
            "type": node_type,
            "tag": tag or f"{node_type.upper()}-{host}:{port}",
            "server": host,
            "server_port": int(port)
        }
        if node_type == "vless":
            node["uuid"] = user_info
        else:
            node["password"] = user_info

        sni = q_params.get("sni", q_params.get("peer", [""]))[0]
        if sni:
            node.setdefault("tls", {})["enabled"] = True
            node["tls"]["server_name"] = sni
        return normalize_proxy_outbound(node)

    return None

def parse_subscription_payload(raw_data: str) -> list:
    """多格式订阅解析器：支持 JSON / Base64 URI 列表 / Clash YAML"""
    raw_data = raw_data.strip()
    # 1. 尝试 JSON
    if raw_data.startswith("{") and raw_data.endswith("}"):
        try:
            parsed = json.loads(raw_data)
            if "outbounds" in parsed:
                return [normalize_proxy_outbound(ob) for ob in parsed["outbounds"]]
        except Exception:
            pass

    # 2. 尝试 Base64 解码
    decoded_text = ""
    try:
        # 补全 padding
        missing_padding = len(raw_data) % 4
        padded = raw_data + ('=' * (4 - missing_padding)) if missing_padding else raw_data
        decoded_bytes = base64.b64decode(padded)
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
        pass

    target_text = decoded_text if ("://" in decoded_text) else raw_data

    # 3. 逐行解析 URI
    nodes = []
    for line in target_text.splitlines():
        line = line.strip()
        if "://" in line:
            node = parse_node_uri(line)
            if node:
                nodes.append(node)

    if nodes:
        return nodes

    # 4. 尝试简易提取 Clash YAML 中的 proxies
    if "proxies:" in raw_data:
        try:
            import re
            # 轻量正则提取 name, type, server, port, password/uuid 等
            # 防止无 PyYAML 环境报错
            clash_nodes = []
            current_proxy = {}
            for line in raw_data.splitlines():
                line = line.strip()
                if line.startswith("- name:") or line.startswith("- {name:"):
                    if current_proxy and "type" in current_proxy:
                        clash_nodes.append(normalize_proxy_outbound(current_proxy))
                    current_proxy = {}
                    m = re.search(r'name:\s*["\']?([^,"\']+)["\']?', line)
                    if m: current_proxy["tag"] = m.group(1).strip()
                elif current_proxy is not None:
                    for k in ["type", "server", "port", "password", "uuid", "sni", "client-fingerprint"]:
                        m = re.search(rf'^{k}:\s*["\']?([^,"\']+)["\']?', line)
                        if m:
                            current_proxy[k] = m.group(1).strip()
            if current_proxy and "type" in current_proxy:
                clash_nodes.append(normalize_proxy_outbound(current_proxy))
            if clash_nodes:
                return clash_nodes
        except Exception:
            pass

    return []

def sanitize_singbox_dict(cfg_dict: dict) -> dict:
    """全自动迁移至 sing-box 1.14.3 规范，清除所有废弃结构与非法字段"""
    if not isinstance(cfg_dict, dict):
        return cfg_dict

    # 1. 迁移 experimental.cache_file
    exp = cfg_dict.setdefault("experimental", {})
    if "cache_file" in exp and isinstance(exp["cache_file"], dict):
        if "store_rdrc" in exp["cache_file"]:
            exp["cache_file"]["store_dns"] = exp["cache_file"].pop("store_rdrc")

    # 2. 迁移 DNS Server 为 1.14.0+ 的 type + server 标准格式，移除废弃顶层 fakeip/independent_cache
    if "dns" in cfg_dict and isinstance(cfg_dict["dns"], dict):
        dns = cfg_dict["dns"]
        dns.pop("fakeip", None)
        dns.pop("independent_cache", None)

        migrated_servers = []
        for s in dns.get("servers", []):
            if not isinstance(s, dict):
                continue
            # 兼容处理旧 address 字段
            if "address" in s:
                addr = s.pop("address")
                tag = s.get("tag", "")
                if addr == "fakeip" or "fakeip" in tag:
                    s["type"] = "fakeip"
                    s.setdefault("inet4_range", "198.18.0.0/15")
                elif addr == "local" or "local" in tag:
                    s["type"] = "local"
                    s["prefer_go"] = True
                elif addr.startswith("https://"):
                    s["type"] = "https"
                    clean_server = addr.replace("https://", "").split("/")[0]
                    s["server"] = clean_server
                elif addr.startswith("rcode://"):
                    continue # 1.14 废弃 rcode 地址
                else:
                    s["type"] = "udp"
                    s["server"] = addr.split("/")[0]
            migrated_servers.append(s)

        # 确保存在直连 DNS (tag: ali 或 local)
        has_direct_dns = any(s.get("tag") in ["ali", "local", "dns-direct"] for s in migrated_servers)
        if not has_direct_dns:
            migrated_servers.insert(0, {
                "tag": "ali",
                "type": "https",
                "server": "223.5.5.5"
            })
        dns["servers"] = migrated_servers

        # 净化 dns.rules (移除已废弃的 outbound 匹配规则)
        if "rules" in dns and isinstance(dns["rules"], list):
            dns["rules"] = [r for r in dns["rules"] if isinstance(r, dict) and "outbound" not in r]

    # 3. 净化 Inbounds: 移除废弃的 sniff 字段，升级 tun address
    for ib in cfg_dict.get("inbounds", []):
        if not isinstance(ib, dict): continue
        ib.pop("sniff", None)
        ib.pop("sniff_override_destination", None)
        if ib.get("type") == "tun":
            if "inet4_address" in ib:
                val = ib.pop("inet4_address")
                if "address" not in ib:
                    ib["address"] = [val] if isinstance(val, str) else val
            if "inet6_address" in ib:
                val6 = ib.pop("inet6_address")
                if "address" in ib and isinstance(ib["address"], list):
                    if isinstance(val6, list): ib["address"].extend(val6)
                    else: ib["address"].append(val6)

    # 4. 彻底移除 1.13+ 废弃的 block / dns 出站，标准化代理节点 (全面支持 anytls)
    valid_outbounds = []
    valid_tags = set()

    for ob in cfg_dict.get("outbounds", []):
        if not isinstance(ob, dict): continue
        otype = ob.get("type", "").lower()
        tag = ob.get("tag", "")

        # 彻底移除废弃的 block 和 dns 出站
        if otype in ["block", "dns"]:
            continue

        if otype in ["direct", "selector", "urltest", "fallback", "loadbalance"] or otype in VALID_PROXY_TYPES:
            # 剥离 urltest 中非法的 default 字段！
            if otype == "urltest":
                ob.pop("default", None)
            # 标准化节点参数
            if otype in VALID_PROXY_TYPES:
                ob = normalize_proxy_outbound(ob)
            valid_outbounds.append(ob)
            if tag:
                valid_tags.add(tag)

    # 确保存在直连出站
    if not any(ob.get("type") == "direct" for ob in valid_outbounds):
        valid_outbounds.append({"tag": "直连", "type": "direct"})
        valid_tags.add("直连")

    # 净化 selector / urltest 的成员列表，并补齐未归组节点
    core_groups = ["自动选择", "手动选择", "默认代理", "proxy"]
    for ob in valid_outbounds:
        otype = ob.get("type", "").lower()
        if otype in ["selector", "urltest", "fallback", "loadbalance"]:
            nodes = ob.get("outbounds", [])
            clean_nodes = [n for n in nodes if n in valid_tags or n in ["直连", "direct", "默认代理", "自动选择", "手动选择"]]
            if not clean_nodes:
                clean_nodes = ["直连" if "直连" in valid_tags else "direct"]
            ob["outbounds"] = clean_nodes
            # selector 若 default 失效则重置为第一个节点
            if otype == "selector":
                if ob.get("default") and ob.get("default") not in clean_nodes:
                    ob["default"] = clean_nodes[0]
            else:
                ob.pop("default", None) # 确保 urltest 绝无 default 字段

    cfg_dict["outbounds"] = valid_outbounds

    # 5. 净化 Route: 移除对 block / dns-out 的引用，转换为 action: reject / hijack-dns
    route = cfg_dict.setdefault("route", {})
    route["auto_detect_interface"] = True # 强制开启，防止测速流量死循环！

    # 动态匹配无代理的直连 DNS 解析器
    direct_resolver_tag = "ali"
    if "dns" in cfg_dict and "servers" in cfg_dict["dns"]:
        for s in cfg_dict["dns"]["servers"]:
            if "detour" not in s and s.get("type") in ["https", "udp", "local"]:
                direct_resolver_tag = s.get("tag", "ali")
                break
    route["default_domain_resolver"] = direct_resolver_tag

    migrated_rules = []
    for r in route.get("rules", []):
        if not isinstance(r, dict): continue
        target_ob = r.get("outbound", "")

        # 映射旧 block 为 action: reject
        if target_ob in ["block", "拒绝"]:
            r.pop("outbound", None)
            r["action"] = "reject"
        # 映射旧 dns-out 为 action: hijack-dns
        elif target_ob in ["dns-out", "dns"] or r.get("protocol") == "dns":
            r.pop("outbound", None)
            r["action"] = "hijack-dns"
        # 针对不存在的出站进行保底回退
        elif target_ob and target_ob not in valid_tags:
            r["outbound"] = "直连" if "直连" in valid_tags else "direct"

        migrated_rules.append(r)

    # 确保 DNS 劫持规则在首位
    has_dns_hijack = any(r.get("action") == "hijack-dns" for r in migrated_rules)
    if not has_dns_hijack:
        migrated_rules.insert(0, {"protocol": "dns", "action": "hijack-dns"})
        migrated_rules.insert(1, {"port": 53, "action": "hijack-dns"})

    route["rules"] = migrated_rules
    return cfg_dict

def sanitize_config_file(filepath: str):
    """就地彻底净化配置文件"""
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        data = sanitize_singbox_dict(data)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        append_log(f"净化配置异常: {e}")

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
        if m in ["x86_64", "amd64"]: return "amd64"
        elif m in ["aarch64", "arm64"]: return "arm64"
        elif "armv7" in m or m == "arm": return "armv7"
        elif m in ["i386", "i686"]: return "386"
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
            parsed = json.loads(config_content)
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
                    err = res.stderr or res.stdout
                    return False, f"Sing-Box 校验未通过:\n{err}"
            except Exception:
                pass
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
        return True, "校验通过"

    def start(self):
        if self.is_running():
            return True, "服务已在运行中"

        self.bin_path = self._find_binary()
        if not os.path.exists(self.bin_path):
            return False, f"未找到 sing-box 核心程序: {self.bin_path}，请先点击安装核心"

        if not os.path.exists(CONFIG_PATH):
            if os.path.exists(PRESET_PATH):
                shutil.copy(PRESET_PATH, CONFIG_PATH)
            else:
                return False, "未找到可用配置文件，请先配置或保存"

        # 启动前执行 1.14 规范自动迁移与就地净化
        sanitize_config_file(CONFIG_PATH)

        # 预先检查语法
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg_text = f.read()
        ok, msg = self.validate_config(cfg_text)
        if not ok:
            append_log(f"启动拦截: 配置未通过验证:\n{msg}")
            return False, msg

        try:
            cmd = [self.bin_path, "run", "-c", CONFIG_PATH]
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            self.start_time = time.time()
            append_log(f"Sing-Box 核心已启动 (PID: {self.process.pid})")

            # 等待 0.4 秒确认内核进程是否存活，防止秒崩
            time.sleep(0.4)
            if self.process.poll() is not None:
                err_out = self.process.stdout.read() if self.process.stdout else "未知错误退出"
                append_log(f"内核异常退出:\n{err_out}")
                self.process = None
                return False, f"Sing-Box 启动即退出:\n{err_out}"

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
            return True, "启动成功"
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
        time.sleep(0.5)
        return self.start()

    def download_kernel(self, custom_url=None):
        arch = self.get_arch()
        version = "1.14.3"
        url = custom_url or f"https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}.tar.gz"

        append_log(f"开始准备下载 sing-box 内核 ({arch})...")
        tar_path = os.path.join(DATA_DIR, f"sing-box-{arch}.tar.gz")

        candidate_urls = [url] if custom_url else [f"https://ghfast.top/{url}", f"https://ghproxy.net/{url}", url]
        download_success = False
        last_error = ""

        for dl_url in candidate_urls:
            try:
                append_log(f"尝试下载链接: {dl_url}")
                req = urllib.request.Request(dl_url, headers={"User-Agent": "Mozilla/5.0 (compatible; SingBoxDashboard/1.0)"})
                with urllib.request.urlopen(req, timeout=25) as resp, open(tar_path, "wb") as f:
                    shutil.copyfileobj(resp, f)
                download_success = True
                break
            except Exception as e:
                last_error = str(e)

        if not download_success:
            return False, f"下载内核失败: {last_error}"

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
            return False, f"解压失败: {e}"

    def get_clash_api_config(self):
        cfg_file = CONFIG_PATH if os.path.exists(CONFIG_PATH) else PRESET_PATH
        if not os.path.exists(cfg_file):
            return "http://127.0.0.1:9090", ""
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            clash_api = data.get("experimental", {}).get("clash_api", {})
            controller = clash_api.get("external_controller", "127.0.0.1:9090")
            secret = clash_api.get("secret", "")
            if not controller.startswith("http"):
                controller = f"http://{controller}"
            return controller, secret
        except Exception:
            return "http://127.0.0.1:9090", ""

    def get_proxies_data(self):
        controller, secret = self.get_clash_api_config()
        if self.is_running() and controller:
            try:
                req = urllib.request.Request(f"{controller}/proxies")
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with DIRECT_OPENER.open(req, timeout=1.5) as resp:
                    clash_data = json.loads(resp.read().decode("utf-8"))
                    proxies = clash_data.get("proxies", {})
                    groups = []
                    nodes_info = {}

                    for name, item in proxies.items():
                        ptype = item.get("type", "").lower()
                        if ptype in ["selector", "urltest", "fallback", "loadbalance"]:
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

        cfg_file = CONFIG_PATH if os.path.exists(CONFIG_PATH) else PRESET_PATH
        if not os.path.exists(cfg_file):
            return {"source": "none", "groups": [], "nodes": {}}

        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                data = json.load(f)

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
                elif ob_type not in ["direct", "block", "dns", "直连", "拒绝", "dns-out"]:
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
                # 必须指定 safe=""，转义包含 / 的节点名字
                put_url = f"{controller}/proxies/{urllib.parse.quote(group_name, safe='')}"
                put_data = json.dumps({"name": node_name}).encode("utf-8")
                req = urllib.request.Request(put_url, data=put_data, method="PUT")
                req.add_header("Content-Type", "application/json")
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with DIRECT_OPENER.open(req, timeout=2) as resp:
                    if resp.status in [200, 204]:
                        switched_live = True
                        append_log(f"已动态切换出站组 [{group_name}] -> {node_name}")
            except Exception as e:
                append_log(f"动态切换未生效 ({e})，将持久化更新配置文件")

        # 仅针对 selector 持久化 default，绝不向 urltest 写入 default
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
                append_log(f"持久化默认节点异常: {e}")

        msg = f"节点已成功切换至: {node_name}"
        if not switched_live and self.is_running():
            msg += " (已保存配置，重启服务后生效)"
        return True, msg

    def test_delay(self, node_name: str):
        controller, secret = self.get_clash_api_config()
        if not (self.is_running() and controller):
            return False, "需先启动 Sing-Box 核心方可进行在线测速"

        try:
            # 必须 safe=""，防止斜杠被保留导致 404
            encoded_node = urllib.parse.quote(node_name, safe="")
            url = f"{controller}/proxies/{encoded_node}/delay?timeout=3000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
            req = urllib.request.Request(url)
            if secret:
                req.add_header("Authorization", f"Bearer {secret}")
            # 使用 DIRECT_OPENER 避免走外部代理干扰本地通信
            with DIRECT_OPENER.open(req, timeout=4) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                return True, res.get("delay", 0)
        except Exception:
            return False, "超时/失败"

manager = SingBoxManager()

class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

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
                cfg_path = CONFIG_PATH if os.path.exists(CONFIG_PATH) else PRESET_PATH
                if os.path.exists(cfg_path):
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        content = f.read()
                else:
                    content = "{}"
                self._send_json({"config": content})
            elif self.path == "/api/preset":
                if os.path.exists(PRESET_PATH):
                    with open(PRESET_PATH, "r", encoding="utf-8") as f:
                        content = f.read()
                else:
                    content = "{}"
                self._send_json({"preset": content})
            elif self.path in ["/api/proxies", "/api/nodes"]:
                self._send_json(manager.get_proxies_data())
            elif self.path.startswith("/api/nodes/delay"):
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)
                node = params.get("node", [""])[0]
                if not node:
                    self._send_json({"success": False, "message": "参数 node 不能为空"}, 400)
                    return
                ok, val = manager.test_delay(node)
                if ok:
                    self._send_json({"success": True, "delay": val})
                else:
                    self._send_json({"success": False, "message": val}, 400)
            else:
                super().do_GET()
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

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
                        self._send_json({"success": False, "message": msg}, 400)
                        return

                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    f.write(config_str)
                append_log("配置文件已保存并完成 1.14 规范自动迁移")
                self._send_json({"success": True, "message": "配置保存成功"})

            elif self.path == "/api/nodes/select":
                data = self._read_body_json()
                group = data.get("group", "")
                node = data.get("node", "")
                if not group or not node:
                    self._send_json({"success": False, "message": "group 和 node 不能为空"}, 400)
                    return
                ok, msg = manager.select_proxy(group, node)
                self._send_json({"success": ok, "message": msg})

            elif self.path == "/api/subscribe/import":
                data = self._read_body_json()
                sub_url = data.get("url", "").strip()
                use_preset = data.get("use_preset", True)

                if not sub_url:
                    self._send_json({"success": False, "message": "订阅链接不能为空"}, 400)
                    return

                append_log(f"正在获取订阅内容: {sub_url}")
                # 仅传 sing-box，避免部分机场面板误判为 Clash 返回 YAML 导致格式混淆
                req = urllib.request.Request(
                    sub_url,
                    headers={"User-Agent": "sing-box/1.14.3"}
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw_data = resp.read().decode("utf-8", errors="ignore")

                # 多格式智能解析器：支持 JSON / Base64单节点链接 / Clash YAML
                extracted_nodes = parse_subscription_payload(raw_data)
                if not extracted_nodes:
                    self._send_json({"success": False, "message": "未能从订阅中识别出有效代理节点，请检查链接或格式"}, 400)
                    return

                valid_external = [
                    ob for ob in extracted_nodes
                    if ob.get("type", "").lower() in VALID_PROXY_TYPES
                ]
                all_tags = [ob["tag"] for ob in valid_external if "tag" in ob]

                if use_preset:
                    with open(PRESET_PATH, "r", encoding="utf-8") as f:
                        preset = json.load(f)

                    # 智能地区归类
                    regions_map = classify_nodes_by_region(valid_external)
                    region_tags_map = {
                        "香港": regions_map["香港"]["nodes"],
                        "日本": regions_map["日本"]["nodes"],
                        "狮城": regions_map["狮城"]["nodes"],
                        "美国": regions_map["美国"]["nodes"],
                        "台湾": regions_map["台湾"]["nodes"],
                    }

                    for ob in preset.get("outbounds", []):
                        tag = ob.get("tag", "")
                        if tag in ["自动选择", "手动选择"]:
                            ob["outbounds"] = all_tags if all_tags else ["直连"]
                        elif tag.endswith("自动") or tag.endswith("手动"):
                            r_key = tag[:2]
                            if r_key in region_tags_map:
                                r_nodes = region_tags_map[r_key]
                                ob["outbounds"] = r_nodes if r_nodes else ["直连"]

                    preset["outbounds"].extend(valid_external)
                    final_config = sanitize_singbox_dict(preset)
                    final_config_str = json.dumps(final_config, indent=2, ensure_ascii=False)
                else:
                    final_config = sanitize_singbox_dict({"outbounds": valid_external})
                    final_config_str = json.dumps(final_config, indent=2, ensure_ascii=False)

                if os.path.exists(CONFIG_PATH):
                    shutil.copy(CONFIG_PATH, os.path.join(DATA_DIR, "config.json.bak"))
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    f.write(final_config_str)

                append_log(f"订阅更新成功！已载入 {len(valid_external)} 个节点 (含 AnyTLS 节点)。")
                manager.restart()
                self._send_json({
                    "success": True,
                    "message": f"订阅更新成功！已载入 {len(valid_external)} 个节点并完成 1.14.3 全自动校验与重载。",
                    "config": final_config_str
                })

            elif self.path == "/api/system/install_kernel":
                data = self._read_body_json()
                custom_url = data.get("url", None)
                ok, msg = manager.download_kernel(custom_url)
                self._send_json({"success": ok, "message": msg})
            else:
                self._send_json({"error": "Not Found"}, 404)
        except Exception as e:
            self._send_json({"success": False, "message": str(e)}, 500)

def run_server(port=9622):
    server_address = ("0.0.0.0", port)
    # 使用 ThreadingHTTPServer 解决多节点并发测速请求堵塞卡死问题！
    httpd = ThreadingHTTPServer(server_address, DashboardHandler)
    append_log(f"Sing-Box WebUI 服务已启动 (多线程引擎)，监听端口: {port}")
    print("=" * 60)
    print(f" Sing-Box WebUI 仪表盘启动成功！")
    print(f" 监听地址: http://0.0.0.0:{port}")
    print(f" 多线程并发测速与 AnyTLS 完整支持已启用")
    print("=" * 60)

    def auto_start_kernel():
        time.sleep(1)
        if not manager.is_running():
            ok, msg = manager.start()
            if ok:
                append_log("开箱自启机制: Sing-Box 核心代理已全自动启动！")
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
