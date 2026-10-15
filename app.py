#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sing-Box WebUI Dashboard
轻量级、低功耗 CPU 友好型 Sing-box 管理面板与订阅处理器
支持可视化节点选择 (Clash API & 本地配置双模切换)、测速与延迟高亮
"""

import os
import sys
import json
import time
import shutil
import tarfile
import urllib.request
import urllib.parse
import urllib.error
import platform
import subprocess
import threading
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from collections import deque

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
PRESET_PATH = os.path.join(BASE_DIR, "templates", "preset_config.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")
BIN_DIR = os.path.join(BASE_DIR, "bin")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BIN_DIR, exist_ok=True)

# 内存日志缓冲队列（最多保存300条，轻量不占内存）
LOG_BUFFER = deque(maxlen=300)

VALID_PROXY_TYPES = {
    "vless", "vmess", "shadowsocks", "trojan", "hysteria", "hysteria2",
    "tuic", "wireguard", "shadowtls", "tor", "ssh", "http", "socks"
}

def sanitize_singbox_dict(cfg_dict):
    """清理与修复配置，消除废弃字段并剔除非标 outbound 类型如 anytls"""
    if not isinstance(cfg_dict, dict):
        return cfg_dict

    # 1. 修复 TUN 1.10+ 地址写法
    for ib in cfg_dict.get("inbounds", []):
        if ib.get("type") == "tun":
            if "inet4_address" in ib:
                val = ib.pop("inet4_address")
                if "address" not in ib:
                    ib["address"] = [val] if isinstance(val, str) else val
            if "inet6_address" in ib:
                val6 = ib.pop("inet6_address")
                if "address" in ib and isinstance(ib["address"], list):
                    if isinstance(val6, list):
                        ib["address"].extend(val6)
                    else:
                        ib["address"].append(val6)

    # 2. 收集与剔除非法出站
    valid_outbounds = []
    valid_tags = set()
    skipped = []

    for ob in cfg_dict.get("outbounds", []):
        otype = ob.get("type", "").lower()
        tag = ob.get("tag", "")
        if otype in ["direct", "block", "dns", "selector", "urltest", "fallback", "loadbalance"] or otype in VALID_PROXY_TYPES:
            valid_outbounds.append(ob)
            if tag:
                valid_tags.add(tag)
        else:
            skipped.append(f"{tag}({otype})")

    if skipped:
        append_log(f"安全净化: 自动过滤 {len(skipped)} 个非标/不支持出站: {', '.join(skipped[:5])}")

    # 3. 净化 selector / urltest 中的 outbounds 列表
    for ob in valid_outbounds:
        otype = ob.get("type", "").lower()
        if otype in ["selector", "urltest", "fallback", "loadbalance"]:
            nodes = ob.get("outbounds", [])
            clean_nodes = [n for n in nodes if n in valid_tags or n in ["direct", "block", "dns", "auto-fast"]]
            if not clean_nodes:
                clean_nodes = ["direct"]
            ob["outbounds"] = clean_nodes
            if ob.get("default") and ob.get("default") not in clean_nodes:
                ob["default"] = clean_nodes[0]

    cfg_dict["outbounds"] = valid_outbounds
    return cfg_dict

def sanitize_config_file(filepath):
    """就地净化已有配置文件"""
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
        # 1. 检查本地 ./bin/sing-box
        local_bin = os.path.join(BIN_DIR, "sing-box" + (".exe" if os.name == "nt" else ""))
        if os.path.exists(local_bin) and os.access(local_bin, os.X_OK | os.F_OK):
            return local_bin
        # 2. 检查系统 PATH
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

        # 启动前自动净化配置 (防止残留 anytls 或已弃用字段)
        sanitize_config_file(CONFIG_PATH)

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
                with urllib.request.urlopen(req, timeout=25) as resp, open(tar_path, "wb") as f:
                    shutil.copyfileobj(resp, f)
                download_success = True
                break
            except Exception as e:
                last_error = str(e)
                append_log(f"此节点下载失败或超时，自动切换下一镜像...")

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
            err = f"下载/解压失败: {e}"
            append_log(err)
            return False, err

    # ---------- 节点选择与 Clash API 交互逻辑 ----------
    def get_clash_api_config(self):
        """解析配置文件中 experimental.clash_api 的设置"""
        cfg_file = CONFIG_PATH if os.path.exists(CONFIG_PATH) else PRESET_PATH
        if not os.path.exists(cfg_file):
            return None, ""
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
        """获取所有策略组及节点信息，支持 Clash API 实时动态获取与本地配置回退"""
        controller, secret = self.get_clash_api_config()
        # 1. 如果内核运行中，尝试向 clash_api 请求动态状态
        if self.is_running() and controller:
            try:
                req = urllib.request.Request(f"{controller}/proxies")
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with urllib.request.urlopen(req, timeout=1.5) as resp:
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
                            # 普通代理节点
                            delay = 0
                            history = item.get("history", [])
                            if history:
                                delay = history[-1].get("delay", 0)
                            nodes_info[name] = {
                                "type": item.get("type", "Proxy"),
                                "delay": delay
                            }

                    if groups:
                        return {
                            "source": "clash_api",
                            "groups": groups,
                            "nodes": nodes_info
                        }
            except Exception:
                pass

        # 2. 回退机制：从静态 config.json 中解析出策略组与节点
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
                elif ob_type not in ["direct", "block", "dns"]:
                    nodes_info[tag] = {
                        "type": ob_type,
                        "delay": 0
                    }

            return {
                "source": "config_file",
                "groups": groups,
                "nodes": nodes_info
            }
        except Exception as e:
            return {"source": "error", "message": str(e), "groups": [], "nodes": {}}

    def select_proxy(self, group_name: str, node_name: str):
        """选择并切换指定策略组的节点"""
        controller, secret = self.get_clash_api_config()
        switched_live = False

        # 1. 尝试通过 Clash API 动态秒切
        if self.is_running() and controller:
            try:
                put_url = f"{controller}/proxies/{urllib.parse.quote(group_name)}"
                put_data = json.dumps({"name": node_name}).encode("utf-8")
                req = urllib.request.Request(put_url, data=put_data, method="PUT")
                req.add_header("Content-Type", "application/json")
                if secret:
                    req.add_header("Authorization", f"Bearer {secret}")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status in [200, 204]:
                        switched_live = True
                        append_log(f"已动态切换出站组 [{group_name}] -> {node_name}")
            except Exception as e:
                append_log(f"动态切换尝试未生效 ({e})，将持久化更新至配置文件")

        # 2. 持久化更新到 config.json
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                updated = False
                for ob in cfg.get("outbounds", []):
                    if ob.get("tag") == group_name:
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
            msg += " (已保存配置，重启服务后生效)"
        return True, msg

    def test_delay(self, node_name: str):
        """测试指定节点延迟"""
        controller, secret = self.get_clash_api_config()
        if not (self.is_running() and controller):
            return False, "需先启动 Sing-Box 核心方可进行在线测速"

        try:
            url = f"{controller}/proxies/{urllib.parse.quote(node_name)}/delay?timeout=3000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
            req = urllib.request.Request(url)
            if secret:
                req.add_header("Authorization", f"Bearer {secret}")
            with urllib.request.urlopen(req, timeout=4) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                return True, res.get("delay", 0)
        except Exception as e:
            return False, f"超时/失败"

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
        if self.path == "/api/status":
            self._send_json(manager.get_status())
        elif self.path == "/api/logs":
            self._send_json(list(LOG_BUFFER))
        elif self.path == "/api/config":
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    content = f.read()
            elif os.path.exists(PRESET_PATH):
                with open(PRESET_PATH, "r", encoding="utf-8") as f:
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
        elif self.path == "/api/proxies" or self.path == "/api/nodes":
            # 获取策略组与节点列表
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

    def do_POST(self):
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
            try:
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
                append_log("配置文件已保存更新")
                self._send_json({"success": True, "message": "配置保存成功"})
            except Exception as e:
                self._send_json({"success": False, "message": str(e)}, 500)

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
            try:
                data = self._read_body_json()
                sub_url = data.get("url", "").strip()
                use_preset = data.get("use_preset", True)

                if not sub_url:
                    self._send_json({"success": False, "message": "订阅链接不能为空"}, 400)
                    return

                append_log(f"正在获取订阅内容: {sub_url}")
                req = urllib.request.Request(
                    sub_url,
                    headers={"User-Agent": "sing-box/1.10.0; clash.meta; v2ray"}
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw_data = resp.read().decode("utf-8", errors="ignore")

                final_config_str = ""
                try:
                    parsed_json = json.loads(raw_data)
                    if "outbounds" in parsed_json:
                        # 严格提取官方支持的合法代理节点
                        valid_external = [
                            ob for ob in parsed_json.get("outbounds", [])
                            if ob.get("type", "").lower() in VALID_PROXY_TYPES
                        ]
                        tags = [ob["tag"] for ob in valid_external if "tag" in ob]

                        if use_preset:
                            with open(PRESET_PATH, "r", encoding="utf-8") as f:
                                preset = json.load(f)

                            for ob in preset.get("outbounds", []):
                                if ob.get("tag") == "auto-fast":
                                    ob["outbounds"] = tags if tags else ["direct"]
                                elif ob.get("tag") == "proxy":
                                    ob["outbounds"] = (["auto-fast"] + tags + ["direct"]) if tags else ["auto-fast", "direct"]

                            preset["outbounds"].extend(valid_external)
                            final_config = sanitize_singbox_dict(preset)
                            final_config_str = json.dumps(final_config, indent=2, ensure_ascii=False)
                        else:
                            final_config = sanitize_singbox_dict(parsed_json)
                            final_config_str = json.dumps(final_config, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    self._send_json({
                        "success": False,
                        "message": "暂只支持返回标准 sing-box 节点格式的订阅链接。若为普通 Base64 或 Clash 订阅，请先通过外部转换器或直接粘贴导出后的 sing-box 配置。"
                    }, 400)
                    return

                if os.path.exists(CONFIG_PATH):
                    shutil.copy(CONFIG_PATH, os.path.join(DATA_DIR, "config.json.bak"))
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    f.write(final_config_str)

                append_log("订阅更新成功，已成功与预设模板融合生成配置，正在自动启动/重载内核...")
                # 自动启动/重启内核，实现真正免操作开箱即用
                manager.restart()
                self._send_json({"success": True, "message": "订阅已更新并自动生效！节点已就绪。", "config": final_config_str})
            except Exception as e:
                err_msg = f"订阅导入失败: {e}"
                append_log(err_msg)
                self._send_json({"success": False, "message": err_msg}, 500)

        elif self.path == "/api/system/install_kernel":
            data = self._read_body_json()
            custom_url = data.get("url", None)
            ok, msg = manager.download_kernel(custom_url)
            self._send_json({"success": ok, "message": msg})
        else:
            self._send_json({"error": "Not Found"}, 404)

def run_server(port=9622):
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, DashboardHandler)
    append_log(f"Sing-Box WebUI 服务已启动，监听端口: {port}")
    print("=" * 60)
    print(f" Sing-Box WebUI 仪表盘启动成功！")
    print(f" 监听地址: http://0.0.0.0:{port}")
    print(f" 本地访问: http://127.0.0.1:{port}")
    print(" 极简低功耗设计，集成节点选择面板，适用平台: amd64 / arm64 / armv7 等")
    print("=" * 60)

    # 自动开箱自启内核 (如果已有配置或预设配置，则自动启动 sing-box 代理)
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
