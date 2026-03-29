import json
import base64
from urllib.parse import urlparse, parse_qs, unquote

def _decode_base64_padding(data: str) -> bytes:
    """Pad base64 string to a multiple of 4 before decoding."""
    data = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)

def parse_proxy_url(url: str) -> dict | None:
    """
    Takes a proxy URI string (vless://, vmess://, trojan://, ss://, hy2://)
    and returns a Sing-box outbound configuration dict, or None if failed.
    """
    try:
        url = url.strip()
        
        if url.startswith("vless://"):
            return _parse_vless(url)
        elif url.startswith("vmess://"):
            return _parse_vmess(url)
        elif url.startswith("trojan://"):
            return _parse_trojan(url)
        elif url.startswith("ss://"):
            return _parse_shadowsocks(url)
        elif url.startswith("hy2://") or url.startswith("hysteria2://"):
            return _parse_hysteria2(url)
        
        return None
    except Exception as e:
        return None

def _parse_vless(url: str) -> dict | None:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
    
    qs = parse_qs(parsed.query)
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": parsed.username,
    }
    
    # Handle reality / tls
    security = qs.get("security", [""])[0]
    if security in ["tls", "reality"]:
        outbound["tls"] = {
            "enabled": True,
            "server_name": qs.get("sni", [""])[0] or parsed.hostname,
            "insecure": (qs.get("allowInsecure", ["0"])[0] == "1")
        }
        
        if security == "reality":
            outbound["tls"]["reality"] = {
                "enabled": True,
                "public_key": qs.get("pbk", [""])[0],
                "short_id": qs.get("sid", [""])[0]
            }
            # Add uTLS
            fp = qs.get("fp", ["chrome"])[0]
            if fp:
                outbound["tls"]["utls"] = {
                    "enabled": True,
                    "fingerprint": fp
                }
    
    # Transport (ws, grpc)
    net = qs.get("type", ["tcp"])[0]
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": qs.get("path", ["/"])[0],
            "headers": {
                "Host": qs.get("host", [""])[0] or (qs.get("sni", [""])[0] if "sni" in qs else parsed.hostname)
            }
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": qs.get("serviceName", [""])[0]
        }
        
    return outbound

def _parse_vmess(url: str) -> dict | None:
    # vmess://base64
    b64_data = url.replace("vmess://", "")
    try:
        decoded = _decode_base64_padding(b64_data).decode('utf-8')
        v = json.loads(decoded)
    except Exception:
        return None
        
    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": v.get("add"),
        "server_port": int(v.get("port")),
        "uuid": v.get("id"),
        "alter_id": int(v.get("aid", 0)),
        "security": v.get("scy", "auto")
    }
    
    if v.get("tls") == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": v.get("sni", "") or v.get("add"),
            "insecure": False
        }
        
        fp = v.get("fp")
        if fp:
            outbound["tls"]["utls"] = {
                "enabled": True,
                "fingerprint": fp
            }
            
    net = v.get("net", "tcp")
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": v.get("path", "/"),
            "headers": {"Host": v.get("host", v.get("add"))}
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": v.get("path", "")
        }
        
    return outbound

def _parse_trojan(url: str) -> dict | None:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
        
    qs = parse_qs(parsed.query)
    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": parsed.username
    }
    
    # Trojan typically uses TLS
    sec = qs.get("security", ["tls"])[0]
    if sec == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": qs.get("sni", [""])[0] or parsed.hostname,
            "insecure": (qs.get("allowInsecure", ["0"])[0] == "1")
        }
        
    net = qs.get("type", ["tcp"])[0]
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": qs.get("path", ["/"])[0],
            "headers": {"Host": qs.get("host", [""])[0] or parsed.hostname}
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": qs.get("serviceName", [""])[0]
        }
        
    return outbound

def _parse_shadowsocks(url: str) -> dict | None:
    # ss://method:password@host:port or ss://base64...
    parsed = urlparse(url)
    
    # If standard URI with method:password in username
    if parsed.username and parsed.hostname and parsed.port:
        auth_str = unquote(parsed.username)
        if ":" in auth_str:
            method, password = auth_str.split(":", 1)
        else:
            # might be base64
            try:
                dec = _decode_base64_padding(auth_str).decode('utf-8')
                method, password = dec.split(":", 1)
            except Exception:
                return None
        server = parsed.hostname
        port = parsed.port
    else:
        # Check if it's ss://base64@host:port or ss://base64...
        # In Sing-box Shadowsocks, it usually expects plugin too, but we will handle standard first.
        try:
            b64_part = url.split("://")[1].split("#")[0]
            if "@" in b64_part:
                auth_b64, hp = b64_part.split("@", 1)
                dec = _decode_base64_padding(auth_b64).decode('utf-8')
                method, password = dec.split(":", 1)
                server, port_str = hp.split(":", 1)
                port = int(port_str.split("/")[0].split("?")[0])
            else:
                dec = _decode_base64_padding(b64_part).decode('utf-8')
                auth, hp = dec.split("@", 1)
                method, password = auth.split(":", 1)
                server, port_str = hp.split(":", 1)
                port = int(port_str.split("/")[0].split("?")[0])
        except Exception:
            return None
            
    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "method": method,
        "password": password
    }

def _parse_hysteria2(url: str) -> dict | None:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
        
    qs = parse_qs(parsed.query)
    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": parsed.username,
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni", [""])[0] or parsed.hostname,
            "insecure": (qs.get("insecure", ["0"])[0] == "1")
        }
    }
    
    # obfs
    obfs = qs.get("obfs", [""])[0]
    if obfs:
        outbound["obfs"] = {
            "type": obfs,
            "password": qs.get("obfs-password", [""])[0]
        }
        
    return outbound


def replace_proxy_remark(url: str, new_remark: str) -> str:
    url = url.strip()
    if url.startswith('vmess://'):
        b64 = url.replace('vmess://', '')
        try:
            import json
            dec = _decode_base64_padding(b64).decode('utf-8')
            v = json.loads(dec)
            v['ps'] = new_remark
            import base64
            enc = base64.b64encode(json.dumps(v, separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return f'vmess://{enc}'
        except Exception:
            return url
    else:
        # Standard URI format with #fragment
        if '#' in url:
            base = url.rsplit('#', 1)[0]
        else:
            base = url
        return f'{base}#{new_remark}'

def extract_host_port(url: str) -> tuple[str, int] | None:
    parsed = parse_proxy_url(url)
    if parsed:
        return parsed.get('server', ''), parsed.get('server_port', 0)
    return None
