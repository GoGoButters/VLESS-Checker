"""Whole system: panel process + worker node + real proxy servers.

Sources list three live proxies (local sing-box servers) and one dead one;
after one worker run the group's webhook must serve exactly the live ones.
"""
import asyncio
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SB = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")
pytestmark = pytest.mark.skipif(not (os.path.exists(SB) and shutil.which("openssl")), reason="sing-box/openssl missing")
U = "0b5d8a5e-1111-4222-8333-944455556666"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Http(BaseHTTPRequestHandler):
    body = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/204":
            self.send_response(204)
            self.end_headers()
        elif self.path == "/sub":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(Http.body.encode())
        else:
            self.send_response(404)
            self.end_headers()


def test_panel_and_node_end_to_end():
    tmp = tempfile.mkdtemp()
    crt, key = f"{tmp}/c.pem", f"{tmp}/k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=t.local"], check=True, capture_output=True)
    web = ThreadingHTTPServer(("127.0.0.1", 0), Http)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    wp = web.server_address[1]

    tls = {"enabled": True, "certificate_path": crt, "key_path": key}
    p_tr, p_vl, p_ss, p_dead = free_port(), free_port(), free_port(), free_port()
    cfg = {"log": {"level": "error"}, "outbounds": [{"type": "direct"}], "inbounds": [
        {"type": "trojan", "listen": "127.0.0.1", "listen_port": p_tr, "users": [{"password": "pw"}], "tls": tls},
        {"type": "vless", "listen": "127.0.0.1", "listen_port": p_vl, "users": [{"uuid": U}], "tls": tls,
         "transport": {"type": "ws", "path": "/ws"}},
        {"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": p_ss, "method": "aes-128-gcm", "password": "pw"},
    ]}
    with open(f"{tmp}/sb.json", "w") as f:
        json.dump(cfg, f)
    sb = subprocess.Popen([SB, "run", "-c", f"{tmp}/sb.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    live = [
        f"trojan://pw@127.0.0.1:{p_tr}?security=tls&sni=t.local&allowInsecure=1#tr",
        f"vless://{U}@127.0.0.1:{p_vl}?security=tls&sni=t.local&allowInsecure=1&type=ws&path=%2Fws#vl",
        f"ss://aes-128-gcm:pw@127.0.0.1:{p_ss}#ss",
    ]
    dead = f"trojan://pw@127.0.0.1:{p_dead}?security=tls&sni=t.local#dead"
    Http.body = "\n".join(live + [dead])

    db = f"{tmp}/panel.db"
    env = {**os.environ, "VPN_DB_PATH": db, "VPN_PIPELINE_TICK_S": "0.5"}
    prep = (
        "import database; from auth import hash_password; from sqlmodel import select\n"
        "database.create_db_and_tables()\n"
        "with database.Session(database.engine) as s:\n"
        f"    s.add(database.Settings(admin_pass_hash=hash_password('pw'), node_api_token='tok'))\n"
        f"    s.add(database.TestUrl(url='http://127.0.0.1:{wp}/204', expect_status=204, min_body_bytes=0))\n"
        "    s.commit()\n")
    subprocess.run([sys.executable, "-c", prep], cwd=ROOT, env=env, check=True)
    port = free_port()
    panel = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(port)], cwd=ROOT, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        c = httpx.Client(base_url=base, timeout=30)
        for _ in range(100):
            try:
                if c.get("/login").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        c.post("/login", data={"password": "pw"})
        c.post("/subscriptions/add", data={"url": f"http://127.0.0.1:{wp}/sub"})
        sid = sqlite3.connect(db).execute("SELECT id FROM subscriptions").fetchone()[0]
        form = {"name": "G", "webhook_path": "hook", "source_ids": [str(sid)], "chunk_size": "2",
                "concurrent_checks_limit": "4", "http_timeout_s": "5", "ping_threshold_ms": "1000",
                "ban_duration_hours": "24", "ban_after_n_failures": "3", "good_proxy_retention_cycles": "3",
                "geo_top_n": "1", **{f"proto_{p}": "1" for p in ("vless", "trojan", "ss")}}
        c.post("/ratings/save", data=form)
        for _ in range(100):
            if sqlite3.connect(db).execute("SELECT pool_size FROM rating_groups").fetchone()[0] == 4:
                break
            time.sleep(0.2)

        sys.path.insert(0, os.path.join(ROOT, "node"))
        os.environ.update(MASTER_URL=base, NODE_TOKEN="tok", NODE_NAME="e2e", SINGBOX_PATH=SB)
        import importlib.util
        spec = importlib.util.spec_from_file_location("node_main", os.path.join(ROOT, "node", "main.py"))
        node_main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(node_main)
        sys.path.remove(os.path.join(ROOT, "node"))  # keep `import main` meaning the panel
        node_main.config.master_url, node_main.config.node_token = base, "tok"

        async def one_run():
            w = node_main.Worker()
            await w.register()
            gid = sqlite3.connect(db).execute("SELECT id FROM rating_groups").fetchone()[0]
            c.post(f"/ratings/{gid}/add-node/{w.node_id}")
            jobs = await w._call("GET", "/api/node/jobs", params={"node_id": w.node_id})
            assert jobs["jobs"][0]["due"]
            await w.run_group(jobs["jobs"][0], jobs["test_urls"], "")
            jobs = await w._call("GET", "/api/node/jobs", params={"node_id": w.node_id})
            assert not jobs["jobs"][0]["due"]
            await w.client.aclose()

        asyncio.run(one_run())
        time.sleep(16)  # rating cache: results become visible within MIN_RECOMPUTE_S
        served = sorted(line.split("#")[0] for line in c.get("/hook").text.splitlines())
        assert served == sorted(u.split("#")[0] for u in live)
    finally:
        panel.terminate()
        sb.kill()
        web.shutdown()
