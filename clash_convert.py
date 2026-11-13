"""Clash/Mihomo proxy entries → share links (so the rest of the pipeline stays URI-only)."""
from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlencode


def _host(server: str) -> str:
    return f"[{server}]" if ":" in server and not server.startswith("[") else server


def _q(params: dict) -> str:
    clean = {k: v for k, v in params.items() if v not in (None, "", False)}
    return urlencode({k: ("1" if v is True else v) for k, v in clean.items()}, quote_via=quote)


def _transport(p: dict) -> dict:
    net = p.get("network") or "tcp"
    out: dict = {"type": net}
    if net == "ws":
        o = p.get("ws-opts") or {}
        out["path"] = o.get("path") or "/"
        host = (o.get("headers") or {}).get("Host")
        if host:
            out["host"] = host
    elif net == "grpc":
        out["serviceName"] = (p.get("grpc-opts") or {}).get("grpc-service-name") or ""
    elif net in ("h2", "http"):
        o = p.get("h2-opts") or p.get("http-opts") or {}
        path = o.get("path")
        out["path"] = path[0] if isinstance(path, list) and path else (path or "")
        host = o.get("host")
        out["host"] = ",".join(host) if isinstance(host, list) else (host or "")
    elif net in ("xhttp", "splithttp"):
        o = p.get("xhttp-opts") or {}
        out["path"] = o.get("path") or "/"
        out["host"] = o.get("host") or ""
        out["mode"] = o.get("mode") or ""
    return out


def _tls_params(p: dict) -> dict:
    out: dict = {}
    reality = p.get("reality-opts") or {}
    if reality.get("public-key"):
        out.update(security="reality", pbk=reality["public-key"], sid=reality.get("short-id") or "")
    elif p.get("tls"):
        out["security"] = "tls"
    else:
        out["security"] = "none"
    sni = p.get("servername") or p.get("sni")
    if sni:
        out["sni"] = sni
    if p.get("client-fingerprint"):
        out["fp"] = p["client-fingerprint"]
    if p.get("skip-cert-verify"):
        out["allowInsecure"] = True
    alpn = p.get("alpn")
    if alpn:
        out["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    return out


def clash_proxy_to_link(p: dict) -> str | None:
    t = str(p.get("type") or "").lower()
    server, port = str(p.get("server") or ""), p.get("port")
    if not server or not port:
        return None
    name = quote(str(p.get("name") or ""))
    hp = f"{_host(server)}:{port}"
    try:
        if t == "vless":
            params = {**_tls_params(p), **_transport(p), "flow": p.get("flow") or "",
                      "encryption": p.get("encryption") or "none"}
            return f"vless://{p['uuid']}@{hp}?{_q(params)}#{name}"
        if t == "trojan":
            params = {**_tls_params({**p, "tls": True}), **_transport(p)}
            return f"trojan://{quote(str(p['password']), safe='')}@{hp}?{_q(params)}#{name}"
        if t == "vmess":
            tr = _transport(p)
            v = {"v": "2", "ps": p.get("name") or "", "add": server, "port": str(port), "id": p["uuid"],
                 "aid": str(p.get("alterId") or 0), "scy": p.get("cipher") or "auto",
                 "net": tr["type"], "path": tr.get("path") or tr.get("serviceName") or "",
                 "host": tr.get("host") or "", "tls": "tls" if p.get("tls") else "",
                 "sni": p.get("servername") or "", "fp": p.get("client-fingerprint") or ""}
            return "vmess://" + base64.b64encode(json.dumps(v, ensure_ascii=False).encode()).decode()
        if t == "ss":
            userinfo = base64.urlsafe_b64encode(f"{p['cipher']}:{p['password']}".encode()).decode().rstrip("=")
            plugin = ""
            if p.get("plugin") == "obfs":
                o = p.get("plugin-opts") or {}
                plugin = f"obfs-local;obfs={o.get('mode', 'http')};obfs-host={o.get('host', '')}"
            elif p.get("plugin") == "v2ray-plugin":
                o = p.get("plugin-opts") or {}
                plugin = f"v2ray-plugin;mode={o.get('mode', 'websocket')};host={o.get('host', '')}"
                if o.get("tls"):
                    plugin += ";tls"
            elif p.get("plugin"):
                return None
            q = f"/?plugin={quote(plugin)}" if plugin else ""
            return f"ss://{userinfo}@{hp}{q}#{name}"
        if t in ("hysteria2", "hy2"):
            params = {"sni": p.get("sni") or "", "insecure": bool(p.get("skip-cert-verify")),
                      "obfs": p.get("obfs") or "", "obfs-password": p.get("obfs-password") or "",
                      "mport": p.get("ports") or ""}
            return f"hysteria2://{quote(str(p.get('password') or ''), safe='')}@{hp}?{_q(params)}#{name}"
        if t == "tuic":
            alpn = p.get("alpn")
            params = {"sni": p.get("sni") or "", "allow_insecure": bool(p.get("skip-cert-verify")),
                      "congestion_control": p.get("congestion-controller") or "",
                      "udp_relay_mode": p.get("udp-relay-mode") or "",
                      "alpn": ",".join(alpn) if isinstance(alpn, list) else (alpn or "")}
            return f"tuic://{p['uuid']}:{quote(str(p.get('password') or ''), safe='')}@{hp}?{_q(params)}#{name}"
        if t == "anytls":
            params = {"sni": p.get("sni") or "", "insecure": bool(p.get("skip-cert-verify"))}
            return f"anytls://{quote(str(p['password']), safe='')}@{hp}?{_q(params)}#{name}"
        if t in ("socks5", "socks"):
            auth = ""
            if p.get("username"):
                auth = quote(str(p["username"]), safe="") + ":" + quote(str(p.get("password") or ""), safe="") + "@"
            return f"socks5://{auth}{hp}#{name}"
    except (KeyError, TypeError):
        return None
    return None
