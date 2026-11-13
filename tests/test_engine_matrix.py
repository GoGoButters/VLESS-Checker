"""Every supported link shape must produce a config the target engine accepts.

Runs `sing-box check` / `xray run -test` on generated configs. Binaries come from
SINGBOX_PATH / XRAY_PATH (skipped when missing).
"""
import base64
import json
import os
import shutil
import subprocess
import tempfile

import pytest

import engine_driver
from engine_driver import build_engine_config, engine_for
from proxy_parsers import parse_proxy_url, proxy_key, replace_proxy_remark, get_proxy_identity

U = "0b5d8a5e-1111-4222-8333-944455556666"
PBK = "SpKCwgvBRbNhfR6c0Xf4Z1dvfyBJ1hHk1oF0qhh3yHs"


def _vmess(**kw):
    base = {"v": "2", "ps": "name", "add": "example.com", "port": "443", "id": U, "aid": "0",
            "scy": "auto", "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""}
    base.update(kw)
    return "vmess://" + base64.b64encode(json.dumps(base).encode()).decode()


SS_USERINFO = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
SOCKS_USERINFO = base64.b64encode(b"user:pass").decode()

CASES = [
    # (link, expected engine)
    (f"vless://{U}@example.com:443?security=reality&sni=www.microsoft.com&pbk={PBK}&sid=ab12&fp=chrome&flow=xtls-rprx-vision&type=tcp#r", "singbox"),
    (f"vless://{U}@example.com:443?security=reality&sni=a.com&pbk={PBK}&sid=ab&spx=%2Fabc&type=grpc&serviceName=gs#r", "singbox"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&fp=firefox&alpn=h2,http/1.1&type=ws&path=%2Fws%3Fed%3D2048&host=a.com#w", "singbox"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=httpupgrade&path=%2Fhu&host=a.com#h", "singbox"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=h2&path=%2Fh2&host=a.com#h2", "singbox"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=quic#q", "singbox"),
    (f"vless://{U}@example.com:80?security=none&type=ws&path=%2F#plain", "singbox"),
    (f"vless://{U}@[2001:db8::1]:443?security=tls&sni=a.com&type=tcp#v6", "singbox"),
    (f"vless://{U}@example.com:2053?security=tls&sni=a.com&type=xhttp&path=%2Fx&host=a.com&mode=auto#x", "xray"),
    (f"vless://{U}@example.com:443?security=reality&sni=a.com&pbk={PBK}&sid=ab&type=xhttp&path=%2Fx&mode=stream-one#xr", "xray"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=splithttp&path=%2Fs#sh", "xray"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=kcp&headerType=wechat-video&seed=s3cr3t#kcp", "xray"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=tcp&headerType=http&path=%2F&host=a.com#hh", "xray"),
    (_vmess(net="kcp", type="srtp", path="seed"), "xray"),
    (_vmess(net="kcp", type="none"), "xray"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=xhttp&path=%2Fx&pcs=e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9#pin", "xray"),
    (f"vless://{U}@example.com:443?security=tls&sni=a.com&type=xhttp&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#ex", "xray"),
    (_vmess(net="ws", path="/vm", host="a.com", tls="tls", sni="a.com"), "singbox"),
    (_vmess(net="grpc", path="svc", tls="tls"), "singbox"),
    (_vmess(net="tcp"), "singbox"),
    (_vmess(net="tcp", type="http", host="a.com", path="/"), "xray"),
    (_vmess(net="xhttp", path="/x", tls="tls"), "xray"),
    (f"vmess://{U}@example.com:443?type=ws&security=tls&path=%2Fw&sni=a.com#uri", "singbox"),
    ("trojan://pass@example.com:443?security=tls&sni=a.com&type=ws&path=%2Ft#t", "singbox"),
    ("trojan://pass@example.com:443?sni=a.com#default-tls", "singbox"),
    ("trojan://pass@example.com:443?security=tls&sni=a.com&type=grpc&serviceName=g#tg", "singbox"),
    (f"trojan://pass@example.com:443?security=reality&sni=a.com&pbk={PBK}&sid=ab#tr", "singbox"),
    ("trojan://pass@example.com:443?security=tls&type=xhttp&path=%2Fx#tx", "xray"),
    (f"ss://{SS_USERINFO}@example.com:8388#sip002", "singbox"),
    ("ss://chacha20-ietf-poly1305:pw@example.com:8388#plain-userinfo", "singbox"),
    ("ss://" + base64.b64encode(b"aes-128-gcm:pw@example.com:8388").decode() + "#legacy", "singbox"),
    ("ss://2022-blake3-aes-128-gcm:" + base64.b64encode(b"0123456789abcdef").decode().replace("=", "%3D") + "@example.com:8388#ss2022", "singbox"),
    (f"ss://{SS_USERINFO}@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Da.com#obfs", "singbox"),
    (f"ss://{SS_USERINFO}@example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Da.com#v2p", "singbox"),
    ("hysteria2://pw@example.com:443?sni=a.com&insecure=1&obfs=salamander&obfs-password=o#h2", "singbox"),
    ("hy2://pw@example.com:443/?sni=a.com#hy2", "singbox"),
    ("hysteria2://pw@example.com:443?mport=20000-30000&sni=a.com#hop", "singbox"),
    ("hysteria2://pw@example.com:443,20000-30000/?sni=a.com#hop2", "singbox"),
    (f"tuic://{U}:pw@example.com:443?congestion_control=bbr&alpn=h3&sni=a.com&udp_relay_mode=native#tuic", "singbox"),
    ("hysteria://example.com:443?protocol=udp&auth=a&peer=a.com&insecure=1&upmbps=50&downmbps=100&alpn=hysteria#h1", "singbox"),
    ("anytls://pw@example.com:443?sni=a.com&insecure=1#any", "singbox"),
    (f"socks://{SOCKS_USERINFO}@example.com:1080#socks", "singbox"),
    ("socks5://user:pass@example.com:1080#s5", "singbox"),
]


def _bin(env, default):
    path = os.environ.get(env, default)
    return path if shutil.which(path) or os.path.exists(path) else None


SINGBOX = _bin("SINGBOX_PATH", engine_driver.SINGBOX_PATH)
XRAY = _bin("XRAY_PATH", engine_driver.XRAY_PATH)


@pytest.mark.parametrize("link,engine", CASES, ids=[c[0][:60] for c in CASES])
def test_link_builds_valid_config(link, engine):
    ob = parse_proxy_url(link)
    assert ob, f"parse failed: {link}"
    assert engine_for(ob) == engine
    eng, cfg, _ = build_engine_config(ob, 23456, bind_interface="")
    binary = SINGBOX if eng == "singbox" else XRAY
    if not binary:
        pytest.skip(f"{eng} binary not available")
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        path = f.name
    try:
        cmd = [binary, "check", "-c", path] if eng == "singbox" else [binary, "run", "-test", "-c", path]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, f"{eng} rejected config:\n{json.dumps(cfg, indent=1)}\n{r.stdout}\n{r.stderr}"
    finally:
        os.unlink(path)


def test_plaintext_vless_on_xray_only_transport_is_rejected_early():
    ob = parse_proxy_url(f"vless://{U}@example.com:80?security=none&type=kcp#k")
    assert engine_for(ob) == "xray"
    with pytest.raises(ValueError):
        build_engine_config(ob, 23456)


def test_plaintext_vless_on_common_transport_goes_to_singbox():
    ob = parse_proxy_url(f"vless://{U}@example.com:80?security=none&type=ws&path=%2F#w")
    assert engine_for(ob) == "singbox"


def test_rejects_garbage():
    for bad in ["vless://nohost", "vmess://!!!", "ss://", "trojan://@:0", "http://x", "",
                "ss://YWVzLTI1Ni1nY206cHc@h:8388/?plugin=unknown-plugin"]:
        assert parse_proxy_url(bad) is None, bad


def test_proxy_key_ignores_remarks():
    a = f"vless://{U}@example.com:443?type=tcp#one"
    b = f"vless://{U}@example.com:443?type=tcp#two"
    assert proxy_key(a) == proxy_key(b)
    v1, v2 = _vmess(ps="first"), _vmess(ps="second")
    assert v1 != v2 and proxy_key(v1) == proxy_key(v2)
    assert proxy_key(replace_proxy_remark(v1, "Новое имя")) == proxy_key(v1)


def test_identity_and_remark():
    link = f"vless://{U}@example.com:443?type=tcp#x"
    assert get_proxy_identity(link) == f"vless://{U}@example.com:443"
    assert replace_proxy_remark(link, "Белые списки - 1").endswith("#%D0%91%D0%B5%D0%BB%D1%8B%D0%B5%20%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B8%20-%201")
