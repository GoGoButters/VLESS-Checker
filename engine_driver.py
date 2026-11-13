"""engine_driver — picks and runs the proxy engine (sing-box or Xray-core).

sing-box checks everything it supports natively. Xray-core is used for what
only Xray implements: xhttp/splithttp and mKCP transports, raw/tcp with HTTP
header obfuscation and VLESS encryption. The parser marks such links with
``_x_*`` keys.

Ports come from an in-process allocator: concurrently started engines can never
be handed the same SOCKS port (a reused port made a test run through someone
else's tunnel and produced false passes).
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import socket
import tempfile

SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")
XRAY_PATH = os.environ.get("XRAY_PATH", "/usr/local/bin/xray")

SINGBOX_TRANSPORTS = {"", "tcp", "ws", "grpc", "http", "httpupgrade", "quic"}
XRAY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "socks"}
PORT_RANGE = (20000, 45000)

_XRAY_NETWORK = {
    "": "raw", "tcp": "raw", "raw": "raw", "ws": "ws", "grpc": "grpc",
    "httpupgrade": "httpupgrade", "xhttp": "xhttp", "splithttp": "xhttp", "kcp": "kcp",
}

_reserved_ports: set[int] = set()
_ssl_contexts: dict = {}


def ssl_context(verify: bool = True):
    """One shared SSL context per mode. A fresh httpx client per check used to
    build its own context and reload the CA bundle each time (~2 MB and real
    CPU per concurrent check)."""
    ctx = _ssl_contexts.get(verify)
    if ctx is None:
        import ssl

        import certifi
        if verify:
            ctx = ssl.create_default_context(cafile=certifi.where())
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        _ssl_contexts[verify] = ctx
    return ctx


def allocate_port() -> int:
    """A free localhost port not handed to any other live engine."""
    for _ in range(200):
        port = random.randint(*PORT_RANGE)
        if port in _reserved_ports:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
        _reserved_ports.add(port)
        return port
    raise RuntimeError("no free port for an engine")


def release_port(port: int) -> None:
    _reserved_ports.discard(port)


# Hints sing-box can safely ignore (cosmetic or covered by its own options).
_SOFT_HINTS = {"_x_spx", "_x_authority", "_x_multi_mode", "_x_pcs", "_x_vcn"}

# share-link mKCP header names → Xray FinalMask mkcp-legacy header names
_KCP_HEADERS = {"none": "", "": "", "srtp": "srtp", "utp": "utp", "wechat-video": "wechat",
                "wechat": "wechat", "dtls": "dtls", "wireguard": "wireguard", "dns": "dns"}


def _has_xray_hints(obj) -> bool:
    if isinstance(obj, dict):
        return any(
            (k.startswith("_x_") and k not in _SOFT_HINTS) or _has_xray_hints(v)
            for k, v in obj.items()
        )
    return False


def needs_xray(outbound: dict) -> bool:
    """True when sing-box cannot check this proxy faithfully."""
    if not outbound or (outbound.get("type") or "").lower() not in XRAY_PROTOCOLS:
        return False
    ttype = ((outbound.get("transport") or {}).get("type") or "").lower()
    return ttype not in SINGBOX_TRANSPORTS or _has_xray_hints(outbound)


def engine_for(outbound: dict) -> str:
    return "xray" if needs_xray(outbound) else "singbox"


def _strip_hints(obj):
    if isinstance(obj, dict):
        return {k: _strip_hints(v) for k, v in obj.items() if not k.startswith("_x_")}
    if isinstance(obj, list):
        return [_strip_hints(v) for v in obj]
    return obj


# --------------------------------------------------------------------------
# sing-box
# --------------------------------------------------------------------------
def build_singbox_config(outbound: dict, socks_port: int, bind_interface: str = "") -> dict:
    out = _strip_hints(outbound)
    tr = out.get("transport")
    if tr and tr.get("type") == "tcp":
        out.pop("transport")  # plain tcp is sing-box's default (no transport block)
    if bind_interface:
        out["bind_interface"] = bind_interface
    return {
        "log": {"disabled": True},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [out],
    }


# --------------------------------------------------------------------------
# Xray
# --------------------------------------------------------------------------
def build_xray_outbound(outbound: dict, bind_interface: str = "") -> dict:
    proto = (outbound.get("type") or "").lower()
    if proto not in XRAY_PROTOCOLS:
        raise ValueError(f"protocol {proto!r} is not supported by Xray")

    server = outbound.get("server") or ""
    port = int(outbound.get("server_port") or 443)
    tls = outbound.get("tls") or {}
    transport = outbound.get("transport") or {}
    ttype = (transport.get("type") or "").lower()
    network = _XRAY_NETWORK.get(ttype, ttype or "raw")
    stream: dict = {"network": network}

    reality = tls.get("reality") or {}
    fp = (tls.get("utls") or {}).get("fingerprint")
    if reality.get("enabled"):
        rs = {"serverName": tls.get("server_name") or server,
              "publicKey": reality.get("public_key", ""),
              "fingerprint": fp or "chrome"}
        if reality.get("short_id"):
            rs["shortId"] = reality["short_id"]
        if tls.get("_x_spx"):
            rs["spiderX"] = tls["_x_spx"]
        stream["security"] = "reality"
        stream["realitySettings"] = rs
    elif tls.get("enabled"):
        ts: dict = {"serverName": tls.get("server_name") or server}
        if tls.get("_x_pcs"):
            ts["pinnedPeerCertSha256"] = tls["_x_pcs"]
        elif tls.get("insecure"):
            # Xray 26 removed allowInsecure: start_engine pins the server's
            # certificate first; without a pin the link cannot be checked.
            raise ValueError("insecure TLS needs a pinned certificate on Xray")
        if tls.get("_x_vcn"):
            ts["verifyPeerCertByName"] = tls["_x_vcn"]
        if fp:
            ts["fingerprint"] = fp
        if tls.get("alpn"):
            ts["alpn"] = tls["alpn"]
        stream["security"] = "tls"
        stream["tlsSettings"] = ts
    else:
        stream["security"] = "none"

    if network == "raw" and transport.get("_x_header"):
        h = transport["_x_header"]
        req: dict = {"path": [h.get("path") or "/"]}
        if h.get("host"):
            req["headers"] = {"Host": h["host"]}
        stream["rawSettings"] = {"header": {"type": "http", "request": req}}
    elif network == "ws":
        ws: dict = {"path": transport.get("path") or "/"}
        host = (transport.get("headers") or {}).get("Host")
        if host:
            ws["host"] = host
        if transport.get("max_early_data"):
            sep = "&" if "?" in ws["path"] else "?"
            ws["path"] += f"{sep}ed={int(transport['max_early_data'])}"
        stream["wsSettings"] = ws
    elif network == "grpc":
        g: dict = {"serviceName": transport.get("service_name") or ""}
        if transport.get("_x_authority"):
            g["authority"] = transport["_x_authority"]
        if transport.get("_x_multi_mode"):
            g["multiMode"] = True
        stream["grpcSettings"] = g
    elif network == "httpupgrade":
        hu: dict = {"path": transport.get("path") or "/"}
        if transport.get("host"):
            hu["host"] = transport["host"]
        stream["httpupgradeSettings"] = hu
    elif network == "xhttp":
        xh: dict = {"path": transport.get("path") or "/"}
        for k in ("host", "mode", "extra"):
            if transport.get(k):
                xh[k] = transport[k]
        stream["xhttpSettings"] = xh
    elif network == "kcp":
        # Xray 26 moved mKCP header/seed into FinalMask; share links point at
        # legacy servers, so emulate legacy obfuscation (seed = AES, header = forgery,
        # neither = the old default XOR).
        header = _KCP_HEADERS.get((transport.get("header") or "").lower(), "")
        seed = transport.get("seed") or ""
        masks = []
        if seed or not header:
            masks.append({"type": "mkcp-legacy", "settings": {"header": "", "value": seed}})
        if header:
            masks.append({"type": "mkcp-legacy", "settings": {"header": header, "value": ""}})
        stream["kcpSettings"] = {}
        stream["finalmask"] = {"udp": masks}

    if bind_interface:
        stream["sockopt"] = {"interface": bind_interface}

    # Xray 26 refuses plaintext VLESS/Trojan to public addresses; such links
    # (only mKCP / HTTP-header ones end up here) cannot be checked.
    if proto in ("vless", "trojan") and stream["security"] == "none" and not outbound.get("_x_encryption"):
        raise ValueError(f"Xray refuses plaintext {proto}")

    if proto == "vless":
        user = {"id": outbound.get("uuid", ""), "encryption": outbound.get("_x_encryption") or "none"}
        if outbound.get("flow"):
            user["flow"] = outbound["flow"]
        settings = {"vnext": [{"address": server, "port": port, "users": [user]}]}
    elif proto == "vmess":
        settings = {"vnext": [{"address": server, "port": port, "users": [{
            "id": outbound.get("uuid", ""), "alterId": int(outbound.get("alter_id") or 0),
            "security": outbound.get("security") or "auto"}]}]}
    elif proto == "trojan":
        settings = {"servers": [{"address": server, "port": port, "password": outbound.get("password", "")}]}
    elif proto == "socks":
        srv: dict = {"address": server, "port": port}
        if outbound.get("username"):
            srv["users"] = [{"user": outbound["username"], "pass": outbound.get("password", "")}]
        settings = {"servers": [srv]}
    else:  # shadowsocks
        settings = {"servers": [{"address": server, "port": port, "method": outbound.get("method", ""),
                                 "password": outbound.get("password", "")}]}

    return {"tag": "proxy", "protocol": proto, "settings": settings, "streamSettings": stream}


def build_xray_config(outbound: dict, socks_port: int, bind_interface: str = "") -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [build_xray_outbound(outbound, bind_interface)],
    }


def build_engine_config(outbound: dict, socks_port: int, bind_interface: str = "") -> tuple[str, dict, str]:
    """(engine, config, binary) for one proxy."""
    bind_interface = bind_interface or os.environ.get("BIND_INTERFACE", "")
    if needs_xray(outbound):
        return "xray", build_xray_config(outbound, socks_port, bind_interface), XRAY_PATH
    return "singbox", build_singbox_config(outbound, socks_port, bind_interface), SINGBOX_PATH


# --------------------------------------------------------------------------
# run / stop
# --------------------------------------------------------------------------
class EngineHandle:
    def __init__(self, engine: str, proc, config_path: str, socks_port: int):
        self.engine = engine
        self.proc = proc
        self.config_path = config_path
        self.socks_port = socks_port

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    async def _stop(self):
        try:
            if self.proc is not None and self.proc.returncode is None:
                self.proc.terminate()
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    self.proc.kill()
                    await self.proc.wait()
        except ProcessLookupError:
            pass
        finally:
            try:
                os.unlink(self.config_path)
            except OSError:
                pass
            release_port(self.socks_port)

    async def stop(self):
        # Shielded: a cancelled check (hard timeout) must still reap the process.
        await asyncio.shield(self._stop())


async def _port_ready(port: int, timeout: float, proc) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout)
    while True:
        if proc.returncode is not None:
            return False
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return True
        except OSError:
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(0.1)


async def fetch_cert_sha256(host: str, port: int, sni: str, timeout: float = 5.0) -> str | None:
    """SHA-256 (hex) of the certificate the server presents, verification off.

    Pinning exactly what the server shows is how an "allowInsecure" link is
    checked on Xray 26, which dropped allowInsecure.
    """
    import hashlib
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    loop = asyncio.get_running_loop()
    sock = None
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout)
        family, stype, proto, _, addr = infos[0]
        sock = socket.socket(family, stype, proto)
        sock.setblocking(False)
        iface = os.environ.get("BIND_INTERFACE", "")
        if iface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
            except (OSError, AttributeError):
                pass
        await asyncio.wait_for(loop.sock_connect(sock, addr), timeout)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=ctx, server_hostname=sni or host), timeout)
        sock = None  # owned by the transport now
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.close()
        return hashlib.sha256(der).hexdigest() if der else None
    except (OSError, asyncio.TimeoutError, ssl.SSLError, IndexError, AttributeError):
        return None
    finally:
        if sock is not None:
            sock.close()


async def _pin_insecure_tls(outbound: dict, timeout: float) -> dict | None:
    """For Xray: replace allowInsecure with a pin of the server's certificate."""
    tls = outbound.get("tls") or {}
    if not (tls.get("enabled") and tls.get("insecure")) or tls.get("_x_pcs") or (tls.get("reality") or {}).get("enabled"):
        return outbound
    pin = await fetch_cert_sha256(outbound.get("server") or "", int(outbound.get("server_port") or 443),
                                  tls.get("server_name") or "", timeout)
    if not pin:
        return None
    return {**outbound, "tls": {**tls, "_x_pcs": pin}}


async def start_engine(outbound: dict, wait_s: float = 4.0) -> EngineHandle | None:
    """Start the right engine on a fresh port and wait for its SOCKS inbound.

    Returns None if the config cannot be built or the engine does not come up.
    """
    if needs_xray(outbound):
        outbound = await _pin_insecure_tls(outbound, timeout=max(2.0, wait_s))
        if outbound is None:
            return None
    try:
        port = allocate_port()
    except RuntimeError:
        return None
    try:
        engine, config, binary = build_engine_config(outbound, port)
    except (ValueError, TypeError, KeyError):
        release_port(port)
        return None

    fd, config_path = tempfile.mkstemp(suffix=".json", prefix=f"{engine}_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "run", "-c", config_path,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        os.unlink(config_path)
        release_port(port)
        return None

    handle = EngineHandle(engine, proc, config_path, port)
    try:
        ready = await _port_ready(port, wait_s, proc)
    except BaseException:
        await handle.stop()
        raise
    if not ready:
        await handle.stop()
        return None
    return handle
