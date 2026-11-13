"""End-to-end: real sing-box/Xray servers on localhost, tester.check_proxy through them.

Skipped when the engine binaries or openssl are missing.
"""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import engine_driver
import tester

U = "0b5d8a5e-1111-4222-8333-944455556666"
SB = os.environ.get("SINGBOX_PATH", engine_driver.SINGBOX_PATH)
XR = os.environ.get("XRAY_PATH", engine_driver.XRAY_PATH)
pytestmark = pytest.mark.skipif(
    not (os.path.exists(SB) and os.path.exists(XR) and shutil.which("openssl")),
    reason="engines/openssl not available",
)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/204":
            self.send_response(204)
            self.end_headers()
        elif self.path == "/big":
            body = b"x" * 5000
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/drip":  # endless trickle: 1 byte per 0.5 s
            self.send_response(200)
            self.send_header("Content-Length", "100000000")
            self.end_headers()
            try:
                for _ in range(10_000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.5)
            except OSError:
                pass
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def env():
    tmp = tempfile.mkdtemp()
    crt, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=test.local",
                    "-addext", "subjectAltName=DNS:test.local"], check=True, capture_output=True)
    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()

    tls = {"enabled": True, "certificate_path": crt, "key_path": key}
    p = {name: free_port(socket.SOCK_DGRAM if name in ("hy2", "tuic", "kcp") else socket.SOCK_STREAM)
         for name in ("vless_ws", "trojan", "ss", "hy2", "vmess_grpc", "tuic", "anytls", "xhttp", "kcp")}
    sb_cfg = {"log": {"level": "error"}, "outbounds": [{"type": "direct"}], "inbounds": [
        {"type": "vless", "listen": "127.0.0.1", "listen_port": p["vless_ws"], "users": [{"uuid": U}],
         "tls": tls, "transport": {"type": "ws", "path": "/ws"}},
        {"type": "trojan", "listen": "127.0.0.1", "listen_port": p["trojan"], "users": [{"password": "pw"}], "tls": tls},
        {"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": p["ss"], "method": "aes-256-gcm", "password": "secret"},
        {"type": "hysteria2", "listen": "127.0.0.1", "listen_port": p["hy2"], "users": [{"password": "pw"}], "tls": tls},
        {"type": "vmess", "listen": "127.0.0.1", "listen_port": p["vmess_grpc"], "users": [{"uuid": U, "alterId": 0}],
         "tls": tls, "transport": {"type": "grpc", "service_name": "svc"}},
        {"type": "tuic", "listen": "127.0.0.1", "listen_port": p["tuic"], "users": [{"uuid": U, "password": "pw"}],
         "tls": {**tls, "alpn": ["h3"]}},
        {"type": "anytls", "listen": "127.0.0.1", "listen_port": p["anytls"], "users": [{"password": "pw"}], "tls": tls},
    ]}
    # Xray 26 servers block private targets by default; the test target is loopback.
    xr_cfg = {"log": {"loglevel": "none"},
              "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
              "inbounds": [
        {"listen": "127.0.0.1", "port": p["xhttp"], "protocol": "vless",
         "settings": {"clients": [{"id": U}], "decryption": "none"},
         "streamSettings": {"network": "xhttp", "security": "tls", "xhttpSettings": {"path": "/x"},
                            "tlsSettings": {"certificates": [{"certificateFile": crt, "keyFile": key}]}}},
        # a "legacy" mKCP server: default XOR obfuscation, as old Xray/V2Ray servers do
        {"listen": "127.0.0.1", "port": p["kcp"], "protocol": "vmess",
         "settings": {"clients": [{"id": U}]},
         "streamSettings": {"network": "kcp", "kcpSettings": {},
                            "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {"header": "", "value": ""}}]}}},
    ]}
    procs = []
    for binary, cfg, args in ((SB, sb_cfg, ["run", "-c"]), (XR, xr_cfg, ["run", "-c"])):
        path = os.path.join(tmp, os.path.basename(binary) + ".json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        procs.append(subprocess.Popen([binary, *args, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1.5)
    yield {"http": http.server_address[1], "ports": p}
    for pr in procs:
        pr.kill()
    http.shutdown()


def _links(p):
    import base64
    vm = base64.b64encode(json.dumps({"v": "2", "add": "127.0.0.1", "port": str(p["vmess_grpc"]), "id": U, "aid": "0",
                                      "net": "grpc", "path": "svc", "tls": "tls", "sni": "test.local",
                                      "allowInsecure": "1"}).encode()).decode()
    kcp = base64.b64encode(json.dumps({"v": "2", "add": "127.0.0.1", "port": str(p["kcp"]), "id": U, "aid": "0",
                                       "net": "kcp", "type": "none"}).encode()).decode()
    ss = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    return {
        "vless+tls+ws": f"vless://{U}@127.0.0.1:{p['vless_ws']}?security=tls&sni=test.local&allowInsecure=1&type=ws&path=%2Fws#a",
        "trojan+tls": f"trojan://pw@127.0.0.1:{p['trojan']}?security=tls&sni=test.local&allowInsecure=1#b",
        "ss": f"ss://{ss}@127.0.0.1:{p['ss']}#c",
        "hysteria2": f"hysteria2://pw@127.0.0.1:{p['hy2']}?sni=test.local&insecure=1#d",
        "vmess+grpc+tls": "vmess://" + vm,
        "tuic": f"tuic://{U}:pw@127.0.0.1:{p['tuic']}?sni=test.local&allow_insecure=1&alpn=h3&congestion_control=bbr#e",
        "anytls": f"anytls://pw@127.0.0.1:{p['anytls']}?sni=test.local&insecure=1#f",
        "vless+xhttp+tls (xray)": f"vless://{U}@127.0.0.1:{p['xhttp']}?security=tls&sni=test.local&allowInsecure=1&type=xhttp&path=%2Fx#g",
        "vmess+kcp (xray)": "vmess://" + kcp,
    }


@pytest.mark.parametrize("name", ["vless+tls+ws", "trojan+tls", "ss", "hysteria2", "vmess+grpc+tls", "tuic",
                                  "anytls", "vless+xhttp+tls (xray)", "vmess+kcp (xray)"])
def test_proxy_passes_through_real_server(env, name):
    link = _links(env["ports"])[name]
    urls = [{"url": f"http://127.0.0.1:{env['http']}/204", "expect_status": 204, "min_body_bytes": 0},
            {"url": f"http://127.0.0.1:{env['http']}/big", "expect_status": 200, "min_body_bytes": 1000}]
    r = asyncio.run(tester.check_proxy(link, urls, ping_threshold_ms=1000, http_timeout_s=8))
    assert r["tests_passed"] == 2 and r["ping_ms"] > 0, r


def test_dead_proxy_fails_fast(env):
    link = f"trojan://pw@127.0.0.1:{free_port()}?security=tls&sni=test.local#dead"
    urls = [{"url": f"http://127.0.0.1:{env['http']}/204", "expect_status": 204, "min_body_bytes": 0}]
    t0 = time.monotonic()
    r = asyncio.run(tester.check_proxy(link, urls, 1000, 5))
    assert r["tests_passed"] == 0 and time.monotonic() - t0 < 5


def test_trickling_body_is_bounded(env, monkeypatch):
    monkeypatch.setattr(tester, "PROXY_TIME_BUDGET_S", 6)
    link = _links(env["ports"])["trojan+tls"]
    urls = [{"url": f"http://127.0.0.1:{env['http']}/drip", "expect_status": 200, "min_body_bytes": 1000}] * 3
    t0 = time.monotonic()
    r = asyncio.run(tester.check_proxy(link, urls, 1000, 3))
    took = time.monotonic() - t0
    assert r["tests_passed"] == 0
    assert took < 12, f"trickle held the check for {took:.1f}s"


def test_batch_returns_result_per_link_and_no_port_leak(env):
    links = list(_links(env["ports"]).values()) * 2
    urls = [{"url": f"http://127.0.0.1:{env['http']}/204", "expect_status": 204, "min_body_bytes": 0}]
    status = {}
    res = asyncio.run(tester.run_proxy_checks(links, urls, 1000, 8, concurrency=6, status=status))
    assert len(res) == len(links) and status["checked"] == len(links)
    assert status["passed"] == len(links), [r for r in res if not r["tests_passed"]]
    assert not engine_driver._reserved_ports
