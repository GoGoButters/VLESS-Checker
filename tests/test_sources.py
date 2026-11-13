import base64

import sources
from pipeline import SOURCE_STATS_WINDOW, _decide_source
from database import GroupSource
from proxy_parsers import parse_proxy_url

LINKS = ["vless://u@h1:443?type=ws#a", "trojan://p@h2:443#b", "ss://YWVzLTEyOC1nY206cHc@h3:8388#c"]


def test_plain_and_base64_bodies():
    plain = "# header\n" + "\n".join(LINKS) + "\nhttps://not-a-proxy\n"
    assert sources.extract_links(plain) == LINKS
    b64 = base64.b64encode("\n".join(LINKS).encode()).decode()
    assert sources.extract_links(b64) == LINKS
    wrapped = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
    assert sources.extract_links(wrapped) == LINKS
    urlsafe = base64.urlsafe_b64encode("\n".join(LINKS).encode()).decode().rstrip("=")
    assert sources.extract_links(urlsafe) == LINKS
    assert sources.extract_links("") == [] and sources.extract_links("<html>nope</html>") == []


def test_clash_yaml():
    yaml_body = """
proxies:
  - {name: v, type: vless, server: 1.2.3.4, port: 443, uuid: 0b5d8a5e-1111-4222-8333-944455556666,
     tls: true, servername: a.com, network: ws, ws-opts: {path: /ws, headers: {Host: a.com}},
     client-fingerprint: chrome}
  - {name: r, type: vless, server: 1.2.3.5, port: 443, uuid: 0b5d8a5e-1111-4222-8333-944455556666,
     tls: true, servername: b.com, reality-opts: {public-key: KEY, short-id: ab}, flow: xtls-rprx-vision}
  - {name: s, type: ss, server: 1.2.3.6, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: h, type: hysteria2, server: 1.2.3.7, port: 443, password: pw, sni: c.com, skip-cert-verify: true}
  - {name: t, type: trojan, server: 1.2.3.8, port: 443, password: pw, sni: d.com}
  - {name: unknown, type: wireguard, server: 1.2.3.9, port: 51820}
"""
    links = sources.extract_links(yaml_body)
    assert len(links) == 5
    parsed = [parse_proxy_url(u) for u in links]
    assert all(parsed)
    assert parsed[0]["transport"]["type"] == "ws" and parsed[0]["tls"]["server_name"] == "a.com"
    assert parsed[1]["tls"]["reality"]["public_key"] == "KEY" and parsed[1]["flow"] == "xtls-rprx-vision"
    assert parsed[2]["method"] == "aes-256-gcm" and parsed[3]["tls"]["insecure"] is True


def test_filter_dedup_signature():
    enabled = {"vless": True, "trojan": False, "ss": True}
    assert sources.filter_protocols(LINKS, enabled) == [LINKS[0], LINKS[2]]
    assert len(sources.dedup(LINKS + ["vless://u@h1:443?type=ws#renamed"])) == 3
    assert sources.source_signature(LINKS) == sources.source_signature(list(reversed(LINKS)))
    assert sources.unpack_links(sources.pack_links(LINKS)) == LINKS


def test_autoskip_decisions():
    gs = GroupSource(group_id=1, subscription_id=1)
    dead = [(10, 0)] * SOURCE_STATS_WINDOW
    assert _decide_source(gs, dead[:-1], "sig") == "test"          # not enough samples yet
    assert _decide_source(gs, dead, "sig") == "disable"
    assert _decide_source(gs, [(10, 1)] + dead, "sig") == "test"   # alive recently
    gs.stats_disabled, gs.disabled_signature = True, "sig"
    assert _decide_source(gs, dead, "sig") == "skip"
    assert _decide_source(gs, dead, "other") == "reenable"
