# -*- coding: utf-8 -*-
"""whut_login.py 回归测试（全离线，不访问真实网络）

运行：python test_whut_login.py   或   python -m unittest -v test_whut_login

覆盖点：
  _api_url 拼装 / 门户探测 / CSRF 双候选 / 登录响应容错 /
  ISP 可达性预检与成功判定 / auto 分支编排 / 凭据文件容错 /
  保活循环自愈 / --check-only 与退出码
"""
import base64
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import subprocess

import requests

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("whut_login", HERE / "whut_login.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


# ---------------------------------------------------------------- 测试替身

class Resp:
    def __init__(self, text="", payload=None, status=200):
        self.text = text
        self._payload = payload
        self.status_code = status
        self.url = ""
        self.content = text.encode("utf-8")

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """按 URL 规则返回响应的假会话，并记录请求序列。

    final_urls 用于模拟"跟随重定向后的最终地址"（real requests 的 r.url）。
    """

    def __init__(self, routes=None, errors=None, final_urls=None):
        self.routes = routes or {}
        self.errors = errors or {}
        self.final_urls = final_urls or {}
        self.calls = []
        self.headers = {}

    def _find(self, url):
        for key, val in self.routes.items():
            if key in url:
                return key, val
        return None, None

    def _maybe_raise(self, url):
        for key, exc in self.errors.items():
            if key in url:
                raise exc

    def _do(self, method, url):
        self.calls.append((method, url))
        self._maybe_raise(url)
        key, r = self._find(url)
        if r is None:
            raise requests.ConnectionError("no route: " + url)
        r.url = self.final_urls.get(key, url)
        return r

    def get(self, url, **kw):
        return self._do("GET", url)

    def post(self, url, **kw):
        return self._do("POST", url)


PORTAL = "http://172.30.21.100"
API_ABS = "http://192.168.85.20/api"


def make_client(session, host="172.30.21.100", nas="52"):
    c = m.WlanClient("u", "p")
    c.session = session
    c.host = host
    c.nas_id = nas
    return c


# ---------------------------------------------------------------- URL 拼装

class TestApiUrl(unittest.TestCase):
    def test_absolute_prefix_used_as_is(self):
        self.assertEqual(m.WlanClient._api_url(PORTAL, API_ABS, "/csrf-token"),
                         API_ABS + "/csrf-token")

    def test_relative_prefix_with_slash(self):
        self.assertEqual(m.WlanClient._api_url(PORTAL, "/api", "/csrf-token"),
                         PORTAL + "/api/csrf-token")

    def test_relative_prefix_without_slash(self):
        self.assertEqual(m.WlanClient._api_url(PORTAL, "api", "/csrf-token"),
                         PORTAL + "/api/csrf-token")

    def test_trailing_slash_stripped(self):
        self.assertEqual(m.WlanClient._api_url(PORTAL, "/api/", "/csrf-token"),
                         PORTAL + "/api/csrf-token")

    def test_empty_prefix_no_double_slash(self):
        self.assertEqual(m.WlanClient._api_url(PORTAL, "", "/csrf-token"),
                         PORTAL + "/csrf-token")

    def test_https_prefix(self):
        self.assertEqual(m.WlanClient._api_url(PORTAL, "https://a.b/api", "/x"),
                         "https://a.b/api/x")


# ---------------------------------------------------------------- 门户探测

class TestFetchPortal(unittest.TestCase):
    def test_redirect_with_nasid(self):
        s = FakeSession(routes={"msftconnecttest": Resp()},
                        final_urls={"msftconnecttest": PORTAL + "/tpl/whut/login.html?nasId=52&x=1"})
        c = make_client(s, host="", nas="")
        self.assertTrue(c._fetch_portal())
        self.assertEqual(c.host, "172.30.21.100")
        self.assertEqual(c.nas_id, "52")

    def test_no_nasid_returns_false(self):
        s = FakeSession(routes={"msftconnecttest": Resp()},
                        final_urls={"msftconnecttest": "http://example.com/"})
        c = make_client(s, host="", nas="")
        self.assertFalse(c._fetch_portal())
        self.assertEqual(c.host, "")

    def test_first_seed_error_falls_through(self):
        s = FakeSession(routes={"qq.com": Resp()},
                        errors={"msftconnecttest": requests.ConnectionError("boom")},
                        final_urls={"qq.com": PORTAL + "/?nasId=7"})
        c = make_client(s, host="", nas="")
        self.assertTrue(c._fetch_portal())
        self.assertEqual(c.nas_id, "7")

    def test_all_seeds_fail(self):
        s = FakeSession(errors={"msftconnecttest": requests.ConnectionError("a"),
                                "qq.com": requests.ConnectionError("b")})
        c = make_client(s, host="", nas="")
        self.assertFalse(c._fetch_portal())


# ---------------------------------------------------------------- WLAN 登录

class TestWlanLogin(unittest.TestCase):
    def _login_routes(self, csrf_payload=None, login_payload=None):
        return {
            "login.html": Resp("portal"),
            "config.js": Resp("host_url = 'http://192.168.85.20/api'"),
            "/csrf-token": Resp(payload=csrf_payload if csrf_payload is not None else {"csrf_token": "T1"}),
            "/account/login": Resp(payload=login_payload if login_payload is not None else {"code": 0, "online": {"Username": "u"}}),
        }

    def test_portal_missing(self):
        c = make_client(FakeSession())
        c._fetch_portal = lambda: False
        self.assertFalse(c.login())

    def test_handshake_error_returns_false(self):
        s = FakeSession(routes=self._login_routes(),
                        errors={"login.html": requests.ConnectionError("refused")})
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertFalse(c.login())

    def test_absolute_api_prefix_success(self):
        s = FakeSession(routes=self._login_routes())
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertTrue(c.login())
        self.assertIn(("GET", API_ABS + "/csrf-token"), s.calls)
        self.assertIn(("POST", API_ABS + "/account/login"), s.calls)

    def test_absolute_fails_then_fallback_same_host(self):
        routes = self._login_routes()
        s = FakeSession(routes=routes, errors={"192.168.85.20": requests.ConnectionError("unreachable")})
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertTrue(c.login())
        self.assertIn(("GET", PORTAL + "/api/csrf-token"), s.calls)
        self.assertIn(("POST", PORTAL + "/api/account/login"), s.calls)

    def test_both_csrf_fail(self):
        routes = self._login_routes()
        s = FakeSession(routes=routes,
                        errors={"192.168.85.20": requests.ConnectionError("x"),
                                PORTAL + "/api/csrf-token": requests.ConnectionError("y")})
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertFalse(c.login())

    def test_csrf_nested_in_data(self):
        s = FakeSession(routes=self._login_routes(csrf_payload={"data": {"csrf_token": "N1"}}))
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertTrue(c.login())

    def test_csrf_no_token_key(self):
        s = FakeSession(routes=self._login_routes(csrf_payload={"code": 0}))
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertFalse(c.login())

    def test_login_response_not_dict(self):
        s = FakeSession(routes=self._login_routes(login_payload=["weird"]))
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertFalse(c.login())          # 关键：不能抛 AttributeError

    def test_login_code_nonzero(self):
        s = FakeSession(routes=self._login_routes(login_payload={"code": 1, "msg": "bad pwd"}))
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertFalse(c.login())

    def test_config_js_missing_falls_back_to_api(self):
        routes = self._login_routes()
        s = FakeSession(routes=routes, errors={"config.js": requests.ConnectionError("404")})
        c = make_client(s)
        c._fetch_portal = lambda: True
        self.assertTrue(c.login())
        self.assertIn(("GET", PORTAL + "/api/csrf-token"), s.calls)


# ---------------------------------------------------------------- ISP

class TestIsp(unittest.TestCase):
    def test_portal_unreachable_skips_http(self):
        s = FakeSession()
        c = m.IspClient("u", "p")
        c.session = s
        old = m._tcp_open
        m._tcp_open = lambda *a, **k: False
        try:
            self.assertFalse(c.login())
            self.assertEqual(s.calls, [])     # 完全没发请求
        finally:
            m._tcp_open = old

    def test_success_marker_ac0(self):
        s = FakeSession({"auth_action": Resp("login_ok")})
        c = m.IspClient("u", "p")
        c.session = s
        old = m._tcp_open
        m._tcp_open = lambda *a, **k: True
        try:
            self.assertTrue(c.login())
            self.assertEqual(s.calls[0][1], m.ISP_PORTAL + m.ISP_AUTH_PATH)
        finally:
            m._tcp_open = old

    def test_both_ac_ids_fail(self):
        s = FakeSession({"auth_action": Resp('{"error":"E2531"}')})
        c = m.IspClient("u", "p")
        c.session = s
        old = m._tcp_open
        m._tcp_open = lambda *a, **k: True
        try:
            self.assertFalse(c.login())
            posts = [u for meth, u in s.calls if meth == "POST"]
            self.assertEqual(len(posts), len(m.ISP_AC_IDS))
        finally:
            m._tcp_open = old

    def test_password_base64_prefix(self):
        c = m.IspClient("u", "p@ss")
        self.assertTrue(c.password.startswith("{B}"))
        self.assertEqual(base64.b64decode(c.password[3:]).decode(), "p@ss")


# ---------------------------------------------------------------- login_once 编排

class TestLoginOnce(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(m, k) for k in ("WlanClient", "IspClient", "is_online_sure")}

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(m, k, v)

    def test_wlan_success(self):
        m.WlanClient = lambda u, p: type("W", (), {"login": lambda self: True})()
        self.assertTrue(m.login_once("wlan", "u", "p"))

    def test_auto_wlan_fail_but_online(self):
        m.WlanClient = lambda u, p: type("W", (), {"login": lambda self: False})()
        m.is_online_sure = lambda: True
        self.assertTrue(m.login_once("auto", "u", "p"))

    def test_auto_goes_isp_when_offline(self):
        calls = []
        m.WlanClient = lambda u, p: type("W", (), {"login": lambda self: False})()
        m.is_online_sure = lambda: False
        m.IspClient = lambda u, p: type("I", (), {"login": lambda self: calls.append("isp") or True})()
        self.assertTrue(m.login_once("auto", "u", "p"))
        self.assertEqual(calls, ["isp"])

    def test_isp_forced(self):
        m.IspClient = lambda u, p: type("I", (), {"login": lambda self: True})()
        self.assertTrue(m.login_once("isp", "u", "p"))


# ---------------------------------------------------------------- 凭据

class TestCredentials(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = m.CONFIG_NAME
        m.CONFIG_NAME = Path(self.tmp) / "config.json"

    def tearDown(self):
        m.CONFIG_NAME = self._orig

    def _write(self, text):
        m.CONFIG_NAME.write_text(text, encoding="utf-8")

    def test_plain(self):
        self._write(json.dumps({"username": "a", "password": "b"}))
        self.assertEqual(m.load_credentials(), ("a", "b"))

    def test_base64_password(self):
        enc = "{B}" + base64.b64encode("secret".encode()).decode()
        self._write(json.dumps({"username": "a", "password": enc}))
        self.assertEqual(m.load_credentials(), ("a", "secret"))

    def test_broken_json_exits(self):
        self._write("{not json")
        with self.assertRaises(SystemExit):
            m.load_credentials()

    def test_not_dict_exits(self):
        self._write('["a"]')
        with self.assertRaises(SystemExit):
            m.load_credentials()

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            m.load_credentials()

    def test_empty_fields_exits(self):
        self._write(json.dumps({"username": "", "password": ""}))
        with self.assertRaises(SystemExit):
            m.load_credentials()


# ---------------------------------------------------------------- 主流程

class TestMain(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(m, k) for k in
                       ("is_online", "login_once", "load_credentials", "is_online_sure")}
        self._argv = sys.argv

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(m, k, v)
        sys.argv = self._argv

    def test_check_only_online(self):
        m.is_online = lambda *a, **k: True
        sys.argv = ["whut_login.py", "--check-only"]
        self.assertEqual(m.main(), 0)

    def test_plain_login_success_exit_0(self):
        m.is_online = lambda *a, **k: False
        m.load_credentials = lambda: ("u", "p")
        m.login_once = lambda *a: True
        sys.argv = ["whut_login.py"]
        self.assertEqual(m.main(), 0)

    def test_plain_login_fail_exit_1(self):
        m.is_online = lambda *a, **k: False
        m.load_credentials = lambda: ("u", "p")
        m.login_once = lambda *a: False
        sys.argv = ["whut_login.py"]
        self.assertEqual(m.main(), 1)

    def test_watch_survives_exceptions(self):
        """保活循环里 login_once 反复抛异常也不能退出。"""
        state = {"calls": 0}

        def boom(*a):
            state["calls"] += 1
            if state["calls"] > 2:
                raise KeyboardInterrupt          # 第 3 次收工
            raise RuntimeError("模拟崩溃")

        m.is_online_sure = lambda: False
        m.login_once = boom
        m.load_credentials = lambda: ("u", "p")
        m.time.sleep = lambda s: None
        sys.argv = ["whut_login.py", "--watch", "30"]
        with self.assertRaises(KeyboardInterrupt):
            m.main()
        self.assertEqual(state["calls"], 3)      # 异常没有中断循环

    def test_watch_login_success_resets_streak(self):
        seq = {"n": 0}

        def flaky(*a):
            seq["n"] += 1
            if seq["n"] >= 2:
                raise KeyboardInterrupt
            return False

        m.is_online_sure = lambda: False
        m.login_once = flaky
        m.load_credentials = lambda: ("u", "p")
        m.time.sleep = lambda s: None
        sys.argv = ["whut_login.py", "--watch", "30"]
        with self.assertRaises(KeyboardInterrupt):
            m.main()
        self.assertEqual(seq["n"], 2)


# ---------------------------------------------------------------- 单实例锁

HOLDER_CODE = """
import importlib.util, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("w", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.LOCK_NAME = Path(sys.argv[2])
print("OK" if m.acquire_watch_lock() else "FAIL", flush=True)
time.sleep(float(sys.argv[3]))
"""


class TestSingleInstance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = m.LOCK_NAME
        m.LOCK_NAME = Path(self.tmp) / "watch.lock"

    def tearDown(self):
        m.release_watch_lock()
        m.LOCK_NAME = self._orig

    def test_acquire_release_cycle(self):
        self.assertTrue(m.acquire_watch_lock())
        m.release_watch_lock()
        self.assertTrue(m.acquire_watch_lock())

    @unittest.skipUnless(os.name == "nt", "文件锁依赖 msvcrt")
    def test_second_process_blocked(self):
        holder = subprocess.Popen(
            [sys.executable, "-c", HOLDER_CODE, str(HERE / "whut_login.py"), str(m.LOCK_NAME), "3"],
            stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "OK")
            self.assertFalse(m.acquire_watch_lock(), "第二个进程不应拿到锁")
        finally:
            holder.wait(timeout=10)
        self.assertTrue(m.acquire_watch_lock(), "前一个进程退出后应能拿到锁")

    @unittest.skipUnless(os.name == "nt", "文件锁依赖 msvcrt")
    def test_watch_refuses_when_locked(self):
        holder = subprocess.Popen(
            [sys.executable, "-c", HOLDER_CODE, str(HERE / "whut_login.py"), str(m.LOCK_NAME), "3"],
            stdout=subprocess.PIPE, text=True)
        try:
            holder.stdout.readline()
            saved = (m.is_online, m.load_credentials, sys.argv)
            m.load_credentials = lambda: ("u", "p")
            sys.argv = ["whut_login.py", "--watch", "30"]
            try:
                self.assertEqual(m.main(), 0)      # 被锁时应安静退出，不进入循环
            finally:
                m.is_online, m.load_credentials, sys.argv = saved
        finally:
            holder.wait(timeout=10)


# ---------------------------------------------------------------- 基础工具

class TestUtils(unittest.TestCase):
    def test_host_ip_is_string(self):
        ip = m.get_host_ip()
        self.assertIsInstance(ip, str)
        self.assertGreater(len(ip), 6)

    def test_tcp_open_false_on_closed_port(self):
        self.assertFalse(m._tcp_open("127.0.0.1", 1, timeout=0.3))

    def test_mac_format(self):
        mac = m.get_mac_address()
        self.assertRegex(mac, r"^([0-9A-F]{2}-){5}[0-9A-F]{2}$")

    def test_session_ignores_proxy(self):
        s = m.new_session()
        self.assertFalse(s.trust_env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
