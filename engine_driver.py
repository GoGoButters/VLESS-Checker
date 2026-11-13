"""engine_driver — выбор и запуск движка проверки прокси (sing-box / Xray-core).

Зачем модуль: sing-box 1.11 не умеет транспорт xhttp/splithttp
(`FATAL: outbounds[0].transport: unknown transport type: xhttp`), а в сетях
с белыми списками живут как раз xhttp-конфиги (CDN-адреса на портах 2053/8443).
Поэтому для транспортов, которых нет в sing-box, проверка идёт через Xray-core,
для остального — по-прежнему sing-box.

Публичное API:
    needs_xray(outbound)                     -> bool
    engine_for(outbound)                     -> "xray" | "singbox"
    build_engine_config(outbound, socks_port)-> (engine, config_dict, binary_path)
    async start_engine(outbound, socks_port, wait_s) -> EngineHandle
    EngineHandle.proc / .config_path / .engine / .socks_port
    async EngineHandle.stop()
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile

SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")
XRAY_PATH = os.environ.get("XRAY_PATH", "/usr/local/bin/xray")

# Транспорты, которые понимает sing-box 1.11 (остальные отдаём Xray).
SINGBOX_TRANSPORTS = {"", "tcp", "raw", "ws", "grpc", "http", "httpupgrade", "quic"}
# Протоколы, которые понимает Xray (hysteria2/tuic — нет, их оставляем sing-box).
XRAY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}

# Xray-имя сети для транспорта из ссылок (sing-box → Xray).
_XRAY_NETWORK = {
    "": "tcp",
    "tcp": "tcp",
    "raw": "tcp",
    "ws": "ws",
    "grpc": "grpc",
    "http": "http",
    "h2": "http",
    "httpupgrade": "httpupgrade",
    "xhttp": "xhttp",
    "splithttp": "xhttp",
}


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _transport_type(outbound: dict) -> str:
    return ((outbound or {}).get("transport") or {}).get("type", "") or ""


def needs_xray(outbound: dict) -> bool:
    """True, если sing-box такой прокси проверить не сможет."""
    if not outbound:
        return False
    proto = (outbound.get("type") or "").lower()
    if proto not in XRAY_PROTOCOLS:
        return False
    return _transport_type(outbound).lower() not in SINGBOX_TRANSPORTS


def engine_for(outbound: dict) -> str:
    return "xray" if needs_xray(outbound) else "singbox"


# --------------------------------------------------------------------------
# sing-box → Xray
# --------------------------------------------------------------------------
def build_xray_outbound(outbound: dict, bind_interface: str = "") -> dict:
    """Преобразует outbound в нотации sing-box в outbound Xray-core."""
    proto = (outbound.get("type") or "").lower()
    if proto not in XRAY_PROTOCOLS:
        raise ValueError(f"protocol {proto!r} не поддерживается Xray")

    server = outbound.get("server") or ""
    port = int(outbound.get("server_port") or 443)
    tls = outbound.get("tls") or {}
    transport = outbound.get("transport") or {}
    ttype = (transport.get("type") or "").lower()
    network = _XRAY_NETWORK.get(ttype, "tcp")

    stream: dict = {"network": network}

    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        stream["security"] = "reality"
        rs = {
            "serverName": tls.get("server_name") or server,
            "publicKey": reality.get("public_key", ""),
            "fingerprint": ((tls.get("utls") or {}).get("fingerprint") or "chrome"),
            "spiderX": "",
        }
        if reality.get("short_id"):
            rs["shortId"] = reality["short_id"]
        stream["realitySettings"] = rs
    elif tls.get("enabled"):
        stream["security"] = "tls"
        ts: dict = {"serverName": tls.get("server_name") or server}
        if tls.get("insecure"):
            ts["allowInsecure"] = True
        fp = (tls.get("utls") or {}).get("fingerprint")
        if fp:
            ts["fingerprint"] = fp
        if tls.get("alpn"):
            ts["alpn"] = tls["alpn"]
        stream["tlsSettings"] = ts
    else:
        stream["security"] = "none"

    if network == "ws":
        ws: dict = {"path": transport.get("path") or "/"}
        headers = transport.get("headers") or {}
        if headers:
            ws["headers"] = headers
        if transport.get("early_data_header_name"):
            ws["maxEarlyData"] = transport.get("max_early_data", 2048)
            ws["earlyDataHeaderName"] = transport["early_data_header_name"]
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc: dict = {"serviceName": transport.get("service_name") or ""}
        if transport.get("authority"):
            grpc["authority"] = transport["authority"]
        if transport.get("multi_mode"):
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc
    elif network == "xhttp":
        xh: dict = {}
        for src, dst in (("path", "path"), ("host", "host"), ("mode", "mode"), ("extra", "extra")):
            if transport.get(src):
                xh[dst] = transport[src]
        if not xh.get("path"):
            xh["path"] = "/"
        stream["xhttpSettings"] = xh
    elif network == "httpupgrade":
        hu: dict = {}
        if transport.get("path"):
            hu["path"] = transport["path"]
        if transport.get("host"):
            hu["host"] = transport["host"]
        stream["httpUpgradeSettings"] = hu
    elif network == "http":
        h2: dict = {}
        if transport.get("path"):
            h2["path"] = transport["path"]
        if transport.get("host"):
            h2["host"] = transport["host"] if isinstance(transport["host"], list) else [transport["host"]]
        stream["httpSettings"] = h2

    if bind_interface:
        stream["sockopt"] = {"interface": bind_interface}

    if proto == "vless":
        user = {"id": outbound.get("uuid", ""), "encryption": "none"}
        if outbound.get("flow"):
            user["flow"] = outbound["flow"]
        settings = {"vnext": [{"address": server, "port": port, "users": [user]}]}
    elif proto == "vmess":
        settings = {"vnext": [{
            "address": server, "port": port,
            "users": [{
                "id": outbound.get("uuid", ""),
                "alterId": int(outbound.get("alter_id") or 0),
                "security": outbound.get("security") or "auto",
            }],
        }]}
    elif proto == "trojan":
        settings = {"servers": [{"address": server, "port": port, "password": outbound.get("password", "")}]}
    else:  # shadowsocks
        settings = {"servers": [{
            "address": server, "port": port,
            "method": outbound.get("method", ""),
            "password": outbound.get("password", ""),
        }]}

    return {"tag": "proxy", "protocol": proto, "settings": settings, "streamSettings": stream}


def build_xray_config(outbound: dict, socks_port: int, bind_interface: str = "") -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [build_xray_outbound(outbound, bind_interface)],
    }


def build_singbox_config(outbound: dict, socks_port: int, bind_interface: str = "") -> dict:
    out = dict(outbound)
    if bind_interface:
        out["bind_interface"] = bind_interface
    return {
        "log": {"disabled": True, "level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [out],
    }


def build_engine_config(outbound: dict, socks_port: int, bind_interface: str = "") -> tuple[str, dict, str]:
    """Возвращает (engine, config, binary_path) для конкретного прокси."""
    bind_interface = bind_interface or os.environ.get("BIND_INTERFACE", "")
    if needs_xray(outbound):
        return "xray", build_xray_config(outbound, socks_port, bind_interface), XRAY_PATH
    return "singbox", build_singbox_config(outbound, socks_port, bind_interface), SINGBOX_PATH


# --------------------------------------------------------------------------
# Запуск / остановка
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

    async def stop(self):
        if self.proc is not None and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=3.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        try:
            os.unlink(self.config_path)
        except Exception:
            pass


async def _port_ready(port: int, timeout: float) -> bool:
    deadline = asyncio.get_event_loop().time() + max(0.0, timeout)
    while True:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            if asyncio.get_event_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.15)


async def start_engine(outbound: dict, socks_port: int, wait_s: float = 4.0) -> EngineHandle | None:
    """Поднимает движок и ждёт, пока SOCKS-порт начнёт принимать соединения.

    Возвращает EngineHandle либо None (конфиг не собрался / процесс упал).
    """
    try:
        engine, config, binary = build_engine_config(outbound, socks_port)
    except Exception:
        return None

    fd, config_path = tempfile.mkstemp(suffix=".json", prefix=f"{engine}_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)

    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except Exception:
        try:
            os.unlink(config_path)
        except Exception:
            pass
        return None

    handle = EngineHandle(engine, proc, config_path, socks_port)
    ready = await _port_ready(socks_port, wait_s)
    if not ready or not handle.alive:
        await handle.stop()
        return None
    return handle
