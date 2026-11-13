"""Proxy share-link parsing.

``parse_proxy_url`` turns a share link into an outbound in sing-box notation.
Parameters only Xray-core understands are carried in ``_x_*`` keys; they make
``engine_driver`` pick Xray and are stripped from sing-box configs.

Supported links: vless, vmess (v2rayN JSON and URI form), trojan,
ss (SIP002, legacy base64, plugins), hysteria2/hy2 (incl. port hopping), tuic,
hysteria (v1), anytls, socks/socks5.
Transports: tcp/raw (+http header obfs), ws (+early data), grpc, httpupgrade,
http/h2, quic, xhttp/splithttp, kcp/mkcp.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import parse_qs, quote, unquote

PREFIXES = {
    "vless": ("vless://",),
    "vmess": ("vmess://",),
    "trojan": ("trojan://",),
    "ss": ("ss://",),
    "hy2": ("hy2://",),
    "hysteria2": ("hysteria2://",),
    "tuic": ("tuic://",),
    "hysteria": ("hysteria://",),
    "anytls": ("anytls://",),
    "socks": ("socks://", "socks5://"),
}
ALL_PREFIXES = tuple(p for ps in PREFIXES.values() for p in ps)

# Engines for transports the share link may name
XRAY_ONLY_TRANSPORTS = {"xhttp", "splithttp", "kcp", "mkcp"}


def protocol_of(url: str) -> str | None:
    low = url[:16].lower()
    for proto, prefixes in PREFIXES.items():
        if low.startswith(prefixes):
            return proto
    return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _b64decode(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def _q(qs: dict, *names: str, default: str = "") -> str:
    for n in names:
        v = qs.get(n)
        if v and v[0] != "":
            return v[0]
    return default


def _truthy(v: str) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def _split_host_port(netloc: str) -> tuple[str, str]:
    """host:port from a netloc without userinfo; IPv6 in brackets allowed.
    The port part is returned raw (it may be a hopping spec like 443,2000-3000)."""
    if netloc.startswith("["):
        end = netloc.find("]")
        host = netloc[1:end]
        rest = netloc[end + 1:]
        return host, rest[1:] if rest.startswith(":") else ""
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        return host, port
    return netloc, ""


def _parse_authority(url: str) -> tuple[str, str, str, dict, str] | None:
    """Split scheme://userinfo@host:port/path?query#frag tolerant to odd ports.

    Returns (userinfo, host, port_raw, query_dict, path).
    """
    try:
        body = url.split("://", 1)[1]
    except IndexError:
        return None
    body = body.split("#", 1)[0]
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    path = ""
    slash = body.find("/")
    if slash >= 0:
        body, path = body[:slash], body[slash:]
    userinfo = ""
    if "@" in body:
        userinfo, body = body.rsplit("@", 1)
    host, port = _split_host_port(body)
    return unquote(userinfo), host.strip(), port.strip(), parse_qs(query, keep_blank_values=True), path


def _port(port_raw: str) -> int | None:
    try:
        p = int(port_raw)
    except (TypeError, ValueError):
        return None
    return p if 0 < p < 65536 else None


def _tls(qs: dict, server: str, security: str, *, default_fp: str = "") -> dict | None:
    """sing-box TLS block from link params (tls / reality)."""
    if security not in ("tls", "reality", "xtls"):
        return None
    tls: dict = {
        "enabled": True,
        "server_name": _q(qs, "sni", "peer", "serverName") or server,
        "insecure": _truthy(_q(qs, "allowInsecure", "insecure", "allow_insecure")),
    }
    fp = _q(qs, "fp", "fingerprint") or default_fp
    if security == "reality":
        tls["reality"] = {"enabled": True, "public_key": _q(qs, "pbk", "publicKey"),
                          "short_id": _q(qs, "sid", "shortId")}
        fp = fp or "chrome"
        spx = _q(qs, "spx", "spiderX")
        if spx:
            tls["_x_spx"] = spx
    if fp and fp != "none":
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    alpn = _q(qs, "alpn")
    if alpn:
        tls["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]
    # Xray 26 replaced allowInsecure with certificate pinning / name override
    pcs = _q(qs, "pcs", "pinnedPeerCertSha256")
    if pcs:
        tls["_x_pcs"] = unquote(pcs).replace(":", "")
    vcn = _q(qs, "vcn", "verifyPeerCertByName")
    if vcn:
        tls["_x_vcn"] = unquote(vcn)
    return tls


def _ws_path(path: str) -> tuple[str, int]:
    """v2rayN puts early data into the path: /ws?ed=2048 → ("/ws", 2048)."""
    m = re.search(r"[?&]ed=(\d+)", path)
    if not m:
        return path, 0
    clean = re.sub(r"[?&]ed=\d+", "", path)
    if "&" in clean and "?" not in clean:
        clean = clean.replace("&", "?", 1)
    return clean or "/", int(m.group(1))


def transport_from_params(net: str, qs: dict, default_host: str = "") -> dict | None:
    """Transport block (sing-box notation; Xray-only fields as _x_*)."""
    net = (net or "tcp").lower()
    path = unquote(_q(qs, "path"))
    host = unquote(_q(qs, "host"))

    if net in ("", "tcp", "raw", "none"):
        if _q(qs, "headerType") == "http":
            return {"type": "tcp", "_x_header": {"type": "http", "path": path or "/",
                                                 "host": [h for h in host.split(",") if h]}}
        return None

    if net == "ws":
        clean, ed = _ws_path(path or "/")
        t: dict = {"type": "ws", "path": clean}
        if host or default_host:
            t["headers"] = {"Host": host or default_host}
        eh = _q(qs, "eh")
        ed_param = _q(qs, "ed")
        if ed_param.isdigit():
            ed = int(ed_param)
        if ed:
            t["max_early_data"] = ed
            t["early_data_header_name"] = eh or "Sec-WebSocket-Protocol"
        return t

    if net == "grpc":
        t = {"type": "grpc", "service_name": unquote(_q(qs, "serviceName", "service_name")) or path.lstrip("/")}
        if _q(qs, "authority"):
            t["_x_authority"] = _q(qs, "authority")
        if _q(qs, "mode") == "multi":
            t["_x_multi_mode"] = True
        return t

    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return t

    if net in ("h2", "http"):
        t = {"type": "http"}
        if path:
            t["path"] = path
        if host:
            t["host"] = [h.strip() for h in host.split(",") if h.strip()]
        return t

    if net == "quic":
        return {"type": "quic"}

    if net in ("xhttp", "splithttp"):
        t = {"type": "xhttp", "path": path or "/"}
        if host:
            t["host"] = host
        if _q(qs, "mode"):
            t["mode"] = _q(qs, "mode")
        extra = unquote(_q(qs, "extra"))
        if extra:
            try:
                obj = json.loads(extra)
                if isinstance(obj, dict) and obj:
                    t["extra"] = obj
            except ValueError:
                pass
        return t

    if net in ("kcp", "mkcp"):
        return {"type": "kcp", "header": _q(qs, "headerType", default="none"),
                "seed": unquote(_q(qs, "seed"))}

    # Unknown transport: keep it, Xray may still understand it
    return {"type": net}


# ---------------------------------------------------------------------------
# protocols
# ---------------------------------------------------------------------------
def _parse_vless(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    uuid_, host, port_raw, qs, _ = a
    port = _port(port_raw)
    if not (uuid_ and host and port):
        return None
    out: dict = {"type": "vless", "tag": "proxy", "server": host, "server_port": port, "uuid": uuid_}
    tls = _tls(qs, host, _q(qs, "security").lower())
    if tls:
        out["tls"] = tls
    flow = _q(qs, "flow")
    if flow:
        out["flow"] = flow
    enc = _q(qs, "encryption")
    if enc and enc != "none":
        out["_x_encryption"] = enc
    pe = _q(qs, "packetEncoding")
    if pe in ("xudp", "packetaddr"):
        out["packet_encoding"] = pe
    t = transport_from_params(_q(qs, "type", default="tcp"), qs, default_host=_q(qs, "sni"))
    if t:
        out["transport"] = t
    return out


def _parse_vmess(url: str) -> dict | None:
    body = url[len("vmess://"):].split("#", 1)[0].strip()
    try:
        v = json.loads(_b64decode(body).decode("utf-8", errors="strict"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        v = None
    if not isinstance(v, dict):
        # URI form: vmess://uuid@host:port?type=ws&security=tls...
        a = _parse_authority(url)
        if not a:
            return None
        uuid_, host, port_raw, qs, _ = a
        port = _port(port_raw)
        if not (uuid_ and host and port):
            return None
        out = {"type": "vmess", "tag": "proxy", "server": host, "server_port": port, "uuid": uuid_,
               "alter_id": int(_q(qs, "alterId", "aid", default="0") or 0),
               "security": _q(qs, "encryption", "scy", default="auto")}
        tls = _tls(qs, host, _q(qs, "security").lower())
        if tls:
            out["tls"] = tls
        t = transport_from_params(_q(qs, "type", default="tcp"), qs)
        if t:
            out["transport"] = t
        return out

    host = str(v.get("add") or "").strip()
    port = _port(str(v.get("port") or ""))
    uuid_ = str(v.get("id") or "").strip()
    if not (host and port and uuid_):
        return None
    try:
        aid = int(v.get("aid") or 0)
    except (TypeError, ValueError):
        aid = 0
    out = {"type": "vmess", "tag": "proxy", "server": host, "server_port": port, "uuid": uuid_,
           "alter_id": aid, "security": str(v.get("scy") or "auto")}
    sec = str(v.get("tls") or "").lower()
    qs = {k: [str(v.get(src) or "")] for k, src in (
        ("sni", "sni"), ("fp", "fp"), ("alpn", "alpn"), ("allowInsecure", "allowInsecure"),
        ("pbk", "pbk"), ("sid", "sid"), ("spx", "spx"))}
    tls = _tls(qs, host, sec)
    if tls:
        out["tls"] = tls
    net = str(v.get("net") or "tcp")
    tqs = {
        "path": [str(v.get("path") or "")],
        "host": [str(v.get("host") or "")],
        "serviceName": [str(v.get("path") or "")],
        "headerType": [str(v.get("type") or "")],
        "mode": [str(v.get("mode") or "")],
        "seed": [str(v.get("path") or "")] if net in ("kcp", "mkcp") else [""],
    }
    t = transport_from_params(net, tqs, default_host=str(v.get("sni") or ""))
    if t:
        out["transport"] = t
    return out


def _parse_trojan(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    password, host, port_raw, qs, _ = a
    port = _port(port_raw)
    if not (password and host and port):
        return None
    out: dict = {"type": "trojan", "tag": "proxy", "server": host, "server_port": port, "password": password}
    tls = _tls(qs, host, (_q(qs, "security") or "tls").lower())
    if tls:
        out["tls"] = tls
    t = transport_from_params(_q(qs, "type", default="tcp"), qs, default_host=_q(qs, "sni"))
    if t:
        out["transport"] = t
    return out


def _ss_plugin(plugin: str) -> tuple[str, str] | None:
    """SIP003 plugin string → (sing-box plugin, plugin_opts)."""
    parts = unquote(plugin).split(";")
    name = parts[0].strip()
    opts = ";".join(p for p in parts[1:] if p)
    if name in ("obfs-local", "simple-obfs", "obfs"):
        return "obfs-local", opts
    if name == "v2ray-plugin":
        return "v2ray-plugin", opts
    return None


def _parse_shadowsocks(url: str) -> dict | None:
    body = url[len("ss://"):].split("#", 1)[0]
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    body = body.rstrip("/")
    qs = parse_qs(query)
    try:
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            userinfo = unquote(userinfo)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                method, password = _b64decode(userinfo).decode("utf-8").split(":", 1)
        else:
            dec = _b64decode(body).decode("utf-8")
            auth, hostport = dec.rsplit("@", 1)
            method, password = auth.split(":", 1)
        host, port_raw = _split_host_port(hostport)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    port = _port(port_raw)
    if not (host and port and method):
        return None
    out: dict = {"type": "shadowsocks", "tag": "proxy", "server": host, "server_port": port,
                 "method": method.lower(), "password": password}
    plugin = _q(qs, "plugin")
    if plugin:
        p = _ss_plugin(plugin)
        if p is None:
            return None  # unsupported plugin: the link cannot be checked faithfully
        out["plugin"], out["plugin_opts"] = p
    return out


def _parse_hysteria2(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    password, host, port_raw, qs, _ = a
    ports = port_raw
    main_port = _port(ports.split(",")[0].split("-")[0]) if ports else 443
    if not (host and main_port):
        return None
    out: dict = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": main_port,
                 "password": password,
                 "tls": {"enabled": True, "server_name": _q(qs, "sni", "peer") or host,
                         "insecure": _truthy(_q(qs, "insecure", "allowInsecure"))}}
    hop = _q(qs, "mport", "ports")
    spec = hop or (ports if ("," in ports or "-" in ports) else "")
    if spec:
        ranges = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                if _port(lo) and _port(hi):
                    ranges.append(f"{int(lo)}:{int(hi)}")
            elif _port(part) and int(part) != main_port:
                ranges.append(f"{int(part)}:{int(part)}")
        if ranges:
            out["server_ports"] = ranges
    alpn = _q(qs, "alpn")
    if alpn:
        out["tls"]["alpn"] = [x for x in alpn.split(",") if x]
    obfs = _q(qs, "obfs")
    if obfs and obfs != "none":
        out["obfs"] = {"type": obfs, "password": _q(qs, "obfs-password", "obfs_password")}
    return out


def _parse_tuic(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    userinfo, host, port_raw, qs, _ = a
    port = _port(port_raw)
    uuid_, _, password = userinfo.partition(":")
    if not (uuid_ and host and port):
        return None
    out: dict = {"type": "tuic", "tag": "proxy", "server": host, "server_port": port,
                 "uuid": uuid_, "password": password or _q(qs, "password"),
                 "tls": {"enabled": True, "server_name": _q(qs, "sni") or host,
                         "insecure": _truthy(_q(qs, "allow_insecure", "insecure", "allowInsecure")),
                         "alpn": [x for x in (_q(qs, "alpn") or "h3").split(",") if x]}}
    cc = _q(qs, "congestion_control", "congestion")
    if cc in ("cubic", "new_reno", "bbr"):
        out["congestion_control"] = cc
    mode = _q(qs, "udp_relay_mode")
    if mode in ("native", "quic"):
        out["udp_relay_mode"] = mode
    return out


def _parse_hysteria(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    _, host, port_raw, qs, _ = a
    port = _port(port_raw.split(",")[0])
    if not (host and port):
        return None

    def _mbps(*names: str, default: int) -> int:
        try:
            return int(re.sub(r"[^0-9]", "", _q(qs, *names)) or default)
        except ValueError:
            return default

    out: dict = {"type": "hysteria", "tag": "proxy", "server": host, "server_port": port,
                 "up_mbps": _mbps("upmbps", "up", default=10),
                 "down_mbps": _mbps("downmbps", "down", default=50),
                 "tls": {"enabled": True, "server_name": _q(qs, "peer", "sni") or host,
                         "insecure": _truthy(_q(qs, "insecure")),
                         "alpn": [x for x in (_q(qs, "alpn") or "hysteria").split(",") if x]}}
    auth = _q(qs, "auth", "auth_str")
    if auth:
        out["auth_str"] = auth
    obfs = _q(qs, "obfsParam", "obfs-password")
    if obfs:
        out["obfs"] = obfs
    return out


def _parse_anytls(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    password, host, port_raw, qs, _ = a
    port = _port(port_raw)
    if not (password and host and port):
        return None
    out = {"type": "anytls", "tag": "proxy", "server": host, "server_port": port, "password": password,
           "tls": {"enabled": True, "server_name": _q(qs, "sni", "peer") or host,
                   "insecure": _truthy(_q(qs, "insecure", "allowInsecure"))}}
    fp = _q(qs, "fp")
    if fp:
        out["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
    return out


def _parse_socks(url: str) -> dict | None:
    a = _parse_authority(url)
    if not a:
        return None
    userinfo, host, port_raw, _, _ = a
    port = _port(port_raw)
    if not (host and port):
        return None
    out: dict = {"type": "socks", "tag": "proxy", "server": host, "server_port": port, "version": "5"}
    if userinfo:
        if ":" not in userinfo:
            try:
                userinfo = _b64decode(userinfo).decode("utf-8")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass
        user, _, password = userinfo.partition(":")
        if user:
            out["username"], out["password"] = user, password
    return out


_PARSERS = {
    "vless": _parse_vless, "vmess": _parse_vmess, "trojan": _parse_trojan,
    "ss": _parse_shadowsocks, "hy2": _parse_hysteria2, "hysteria2": _parse_hysteria2,
    "tuic": _parse_tuic, "hysteria": _parse_hysteria, "anytls": _parse_anytls,
    "socks": _parse_socks,
}


def parse_proxy_url(url: str) -> dict | None:
    """Share link → outbound dict (sing-box notation + _x_* hints) or None."""
    try:
        url = (url or "").strip()
        proto = protocol_of(url)
        return _PARSERS[proto](url) if proto else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# identity / naming
# ---------------------------------------------------------------------------
def proxy_key(url: str) -> str:
    """Dedup key: the link without its remark. For vmess the remark ("ps") lives
    inside the base64 JSON, so the JSON is normalized without it."""
    url = (url or "").strip()
    if url.startswith("vmess://"):
        body = url[8:].split("#", 1)[0]
        try:
            v = json.loads(_b64decode(body).decode("utf-8"))
            if isinstance(v, dict):
                v.pop("ps", None)
                return "vmess://" + json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass
    return url.split("#", 1)[0]


def get_proxy_identity(url: str) -> str:
    """Coarse identity used to merge results in ratings: protocol, credential,
    server and port (ignores remark and transport details)."""
    p = parse_proxy_url(url)
    if p:
        user = p.get("uuid") or p.get("password") or ""
        return f"{p['type']}://{user}@{p.get('server', '')}:{p.get('server_port', 0)}"
    return proxy_key(url)


def replace_proxy_remark(url: str, new_remark: str) -> str:
    """Set the display name of a share link (vmess: the "ps" field)."""
    url = url.strip()
    if url.startswith("vmess://"):
        body = url[8:].split("#", 1)[0]
        try:
            v = json.loads(_b64decode(body).decode("utf-8"))
            v["ps"] = new_remark
            return "vmess://" + base64.b64encode(json.dumps(v, ensure_ascii=False).encode()).decode()
        except (ValueError, binascii.Error, UnicodeDecodeError, TypeError):
            pass
    return f"{url.split('#', 1)[0]}#{quote(new_remark)}"
