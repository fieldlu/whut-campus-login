#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""武汉理工大学校园网双网自动登录器

支持两种校园网，自动识别、自动登录、可选保活：

1. WHUT-WLAN（教学办公区无线，tpl/whut 门户）
   - 探测重定向拿到 nasId 与门户 host
   - GET /tpl/whut/login.html            -> 会话 cookie
   - GET /tpl/whut/static/js/config.js   -> 解析 api_base_path
   - GET {api_base}/csrf-token           -> CSRF 令牌
   - POST {api_base}/account/login       -> code==0 即成功
   协议来源: FeliksLv01/WHUT-WLAN, lxidea/whut-online-keeper (Apache-2.0)

2. WHUT-ISP（宿舍区，深澜 srun 门户 172.30.16.34）
   - POST /include/auth_action.php, ac_id 依次尝试 0/5
   - 密码以 {B}+base64 提交，成功标记 login_ok/successful
   协议来源: PGA1293/WHUT-WLAN-DORM, MuZiCul/Login_whut

用法:
    python whut_login.py                       # 自动识别网络并登录（已联网则退出）
    python whut_login.py --net isp             # 强制走 WHUT-ISP
    python whut_login.py --net wlan            # 强制走 WHUT-WLAN
    python whut_login.py --watch               # 保活模式：掉线自动重连
    python whut_login.py --check-only          # 仅检测联网状态
    python whut_login.py --init-config         # 交互式生成 config.json

依赖: 仅 requests
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import requests

log = logging.getLogger("whut-login")

# ---------------------------------------------------------------- 常量

PROBE_HTTPS = "https://www.baidu.com/"          # HTTPS 探针：未认证时门户劫持 HTTP，HTTPS 握手会失败
REDIRECT_SEEDS = [                               # 触发门户重定向的种子 URL（须国内可达且稳定的 HTTP 站点）
    "http://www.msftconnecttest.com/redirect",
    "http://www.qq.com/",
]

WLAN_PORTAL_HINT = "tpl/whut"                    # WLAN 门户页面特征
ISP_PORTAL = "http://172.30.16.34"               # srun 门户
ISP_AUTH_PATH = "/include/auth_action.php"
ISP_REFERER = ISP_PORTAL + "/srun_portal_pc.php?ac_id=5&url=1.1.1.1"
ISP_AC_IDS = (0, 5)
ISP_SUCCESS_MARKERS = ("login_ok", "successful")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
CONFIG_NAME = Path(__file__).resolve().parent / "config.json"


# ---------------------------------------------------------------- 工具

def new_session() -> requests.Session:
    """绕过系统代理（本机常有 Clash 类代理，未认证时绝不能走代理）。"""
    s = requests.Session()
    s.trust_env = False
    s.headers["User-Agent"] = USER_AGENT
    return s


def is_online(timeout: float = 4.0) -> bool:
    try:
        r = new_session().get(PROBE_HTTPS, timeout=timeout)
        return 200 <= r.status_code < 400
    except requests.RequestException:
        return False


def is_online_sure() -> bool:
    """二次确认的在线判定：第一次失败后等 3 秒重试，避免瞬时抖动误判触发登录。"""
    if is_online():
        return True
    time.sleep(3)
    return is_online()


def get_host_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def get_mac_address() -> str:
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return "-".join(mac[i:i + 2] for i in range(0, 12, 2)).upper()


def get_ssid() -> str:
    """Windows 下读取当前 Wi-Fi SSID（仅作日志展示，失败不影响登录）。"""
    if sys.platform != "win32":
        return "?"
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, timeout=8,
        ).stdout.decode("gbk", errors="replace")
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
        return m.group(1).strip() if m else "(未连接 Wi-Fi / 有线)"
    except Exception:
        return "?"


# ---------------------------------------------------------------- WHUT-WLAN（教学办公区，tpl/whut 门户）

class WlanClient:
    def __init__(self, username: str, password: str, timeout: float = 6.0):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = new_session()
        self.host = ""
        self.nas_id = ""

    def _fetch_portal(self) -> bool:
        """跟随 HTTP 重定向拿到门户 host 与 nasId。"""
        for seed in REDIRECT_SEEDS:
            try:
                r = self.session.get(seed, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            final = r.url
            m = re.search(r"[?&]nasId=([^&]+)", final or "")
            if m:
                host = urlparse(final).netloc
                if not host:
                    continue
                self.host = host
                self.nas_id = m.group(1)
                log.info("WLAN 门户: %s, nasId=%s (SSID=%s)", self.host, self.nas_id, get_ssid())
                return True
        return False

    def login(self) -> bool:
        if not self._fetch_portal():
            log.info("未检测到 WLAN 门户重定向（可能不在 WHUT-WLAN 下）")
            return False
        s, host = self.session, self.host
        base = f"http://{host}"

        # 1) 握手拿 cookie
        s.get(f"{base}/tpl/whut/login.html?nasId={self.nas_id}", timeout=self.timeout)

        # 2) 从 config.js 解析 API 前缀
        api_base = ""
        try:
            js = s.get(f"{base}/tpl/whut/static/js/config.js", timeout=self.timeout).text
            m = re.search(r"host_url\s*=\s*['\"](.*?)['\"]", js)
            if m:
                api_base = m.group(1).strip()
        except requests.RequestException:
            pass
        api_base = api_base or "/api"
        log.info("WLAN API 前缀: %s", api_base)

        # 3) CSRF 令牌
        csrf = ""
        try:
            r = s.get(
                f"{base}{api_base}/csrf-token", timeout=self.timeout,
                headers={"Referer": f"{base}/tpl/whut/login.html?nasId={self.nas_id}"},
            )
            csrf = r.json().get("csrf_token", "")
        except (requests.RequestException, ValueError) as e:
            log.warning("获取 CSRF 失败: %s", e)
        if not csrf:
            log.error("CSRF 令牌为空，WLAN 登录中止")
            return False

        # 4) 登录
        data = {
            "username": self.username,
            "password": self.password,
            "swtichip": "",
            "nasId": self.nas_id,
            "userIpv4": "",
            "userMac": "",
            "captcha": "",
            "captchaId": "",
        }
        headers = {
            "Referer": f"{base}/tpl/whut/login.html?nasId={self.nas_id}",
            "Origin": base,
            "X-Requested-With": "XMLHttpRequest",
            "X-Csrf-Token": csrf,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            r = s.post(f"{base}{api_base}/account/login", data=data,
                       headers=headers, timeout=self.timeout)
            body = r.json()
        except (requests.RequestException, ValueError) as e:
            log.error("WLAN 登录请求异常: %s", e)
            return False
        if body.get("code") == 0:
            info = body.get("online") or {}
            log.info("WHUT-WLAN 登录成功 | 用户 %s | IP %s | 本机 %s",
                     info.get("Username", self.username), info.get("UserIpv4", "?"), get_host_ip())
            return True
        log.error("WLAN 登录失败: code=%s msg=%s", body.get("code"), body.get("msg"))
        return False


# ---------------------------------------------------------------- WHUT-ISP（宿舍区，srun 门户）

class IspClient:
    def __init__(self, username: str, password: str, timeout: float = 3.0):
        self.username = username
        self.password = "{B}" + base64.b64encode(password.encode()).decode()
        self.timeout = timeout
        self.session = new_session()

    def _try_ac(self, ac_id: int) -> bool:
        data = {
            "action": "login",
            "ajax": "1",
            "ac_id": str(ac_id),
            "nas_ip": "",
            "username": self.username,
            "password": self.password,
            "save_me": "1",
            "user_ip": "",
            "user_mac": get_mac_address(),
        }
        headers = {
            "Referer": ISP_REFERER,
            "Origin": ISP_PORTAL,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        }
        try:
            r = self.session.post(ISP_PORTAL + ISP_AUTH_PATH, data=data,
                                  headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            log.warning("ISP ac_id=%s 请求异常: %s", ac_id, e)
            return False
        body = r.content.decode("utf-8", errors="replace")
        if any(m in body for m in ISP_SUCCESS_MARKERS):
            log.info("WHUT-ISP 登录成功 | ac_id=%s | IP %s | MAC %s (SSID=%s)",
                     ac_id, get_host_ip(), get_mac_address(), get_ssid())
            return True
        log.info("ISP ac_id=%s 未成功: %s", ac_id, body[:120])
        return False

    def login(self) -> bool:
        for ac_id in ISP_AC_IDS:
            if self._try_ac(ac_id):
                return True
        return False


# ---------------------------------------------------------------- 配置与主流程

def load_credentials() -> tuple[str, str]:
    if CONFIG_NAME.exists():
        d = json.loads(CONFIG_NAME.read_text(encoding="utf-8"))
        user, pwd = d.get("username", ""), d.get("password", "")
        if pwd.startswith("{B}"):
            pwd = base64.b64decode(pwd[3:]).decode("utf-8")
        if user and pwd:
            return user, pwd
    log.error("缺少凭据：请先运行 --init-config 生成 %s", CONFIG_NAME)
    sys.exit(1)


def init_config() -> None:
    user = input("校园网账号(学号/工号): ").strip()
    pwd = input("密码: ").strip()
    CONFIG_NAME.write_text(
        json.dumps({"username": user, "password": pwd}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"已写入 {CONFIG_NAME}（注意：明文保存，勿提交到仓库）")


def login_once(net: str, user: str, pwd: str) -> bool:
    if net == "wlan":
        return WlanClient(user, pwd).login()
    if net == "isp":
        return IspClient(user, pwd).login()
    # auto：先试 WLAN 重定向探测；失败后二次确认是否真离线，防止误判触发登录顶掉会话
    if WlanClient(user, pwd).login():
        return True
    if is_online_sure():
        log.info("二次确认：实际在线，跳过本次登录（避免顶掉已有会话）")
        return True
    log.info("转试 WHUT-ISP ...")
    return IspClient(user, pwd).login()


def main() -> int:
    ap = argparse.ArgumentParser(description="武汉理工校园网双网(WLAN/ISP)自动登录")
    ap.add_argument("--net", choices=["auto", "wlan", "isp"], default="auto",
                    help="指定网络，默认 auto 自动识别")
    ap.add_argument("--watch", nargs="?", const=300, type=int, metavar="SEC",
                    help="保活模式，每 SEC 秒检测一次（默认 300）")
    ap.add_argument("--check-only", action="store_true", help="仅检测联网状态")
    ap.add_argument("--init-config", action="store_true", help="交互式生成凭据文件")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")

    if args.init_config:
        init_config()
        return 0

    if args.check_only:
        print("在线" if is_online() else "离线", f"(SSID={get_ssid()})")
        return 0

    user, pwd = load_credentials()

    if args.watch:
        interval = max(30, args.watch)
        log.info("保活模式启动，检测间隔 %ss（Ctrl+C 退出）", interval)
        fail_streak = 0
        while True:
            try:
                if is_online_sure():
                    if fail_streak:
                        log.info("网络已恢复（此前连续失败 %d 次）", fail_streak)
                    fail_streak = 0
                    log.info("在线，无需登录")
                else:
                    log.info("离线（二次确认），尝试登录 (%s) ...", args.net)
                    ok = login_once(args.net, user, pwd)
                    if ok:
                        fail_streak = 0
                        log.info("登录成功")
                    else:
                        fail_streak += 1
                        log.warning("本次登录未成功（连续第 %d 次），%ds 后重试", fail_streak, interval)
            except KeyboardInterrupt:
                raise
            except Exception as e:                       # noqa: BLE001 - 保活进程必须自愈
                fail_streak += 1
                log.error("保活循环异常（连续第 %d 次）：%s: %s", fail_streak, type(e).__name__, e)
                log.debug("异常详情", exc_info=True)
            time.sleep(interval)
    else:
        if is_online():
            log.info("已在线，无需登录 (SSID=%s)", get_ssid())
            return 0
        ok = login_once(args.net, user, pwd)
        return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.info("已停止")
        sys.exit(130)
    except Exception as e:                               # noqa: BLE001
        log.error("未捕获异常：%s: %s", type(e).__name__, e)
        log.debug("异常详情", exc_info=True)
        sys.exit(1)
