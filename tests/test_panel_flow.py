"""Panel end-to-end: sources → group pools → node jobs → results → webhooks.

Runs the real app (lifespan, scheduler) on a temporary database with local
HTTP sources. Two groups share one node but have different sources: their
pools, results and webhooks must stay independent.
"""
import base64
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

TMP = tempfile.mkdtemp()
os.environ["VPN_DB_PATH"] = os.path.join(TMP, "panel.db")

U = "0b5d8a5e-1111-4222-8333-9444555566{:02d}"
SUB1 = [f"vless://{U.format(i)}@10.0.0.{i}:443?security=tls&sni=a.com&type=ws&path=%2F#s1-{i}" for i in range(1, 11)]
SUB2 = [f"trojan://pw{i}@10.0.1.{i}:443?sni=b.com#s2-{i}" for i in range(1, 6)]
CONTENT = {
    "/sub1": "\n".join(SUB1),
    "/sub2": base64.b64encode("\n".join(SUB2).encode()).decode(),
    "/ss-only": "ss://YWVzLTI1Ni1nY206cHc@10.0.2.1:8388#ss",
}


class Src(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = CONTENT.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture(scope="module")
def panel():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Src)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    import database
    from auth import hash_password
    from sqlmodel import Session
    database.create_db_and_tables()
    with Session(database.engine) as s:
        s.add(database.Settings(admin_pass_hash=hash_password("pw"), node_api_token="tok"))
        s.add(database.TestUrl(url="https://example.com/", expect_status=200, min_body_bytes=0))
        s.commit()

    import pipeline
    pipeline.TICK_S = 0.2
    import rating
    rating.MIN_RECOMPUTE_S = 0
    import main
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        assert c.post("/login", data={"password": "pw"}, follow_redirects=False).status_code == 302
        yield c, base
    srv.shutdown()


H = {"Authorization": "Bearer tok"}


def _wait(pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.2)
    return False


def _groups():
    import database
    from sqlmodel import Session, select
    with Session(database.engine) as s:
        return {g.name: g for g in s.exec(select(database.RatingGroup)).all()}


def _form(name, path, sources, **extra):
    data = {"name": name, "webhook_path": path, "schedule_interval_minutes": "0",
            "good_proxy_retention_cycles": "2", "ban_duration_hours": "24", "ban_after_n_failures": "2",
            "ping_threshold_ms": "1000", "concurrent_checks_limit": "10", "http_timeout_s": "5",
            "speed_test_top_n": "0", "chunk_size": "4", "max_proxies": "0", "geo_top_n": "1",
            "auto_add_new_sources": "1", "source_ids": [str(s) for s in sources]}
    for p in ("vless", "vmess", "trojan", "ss", "hy2", "hysteria2", "tuic", "hysteria", "anytls", "socks"):
        data[f"proto_{p}"] = "1"
    data.update(extra)
    return data


def test_full_flow(panel):
    c, base = panel
    # sources
    r = c.post("/subscriptions/add", data={"url": f"{base}/sub1\n{base}/sub2\n{base}/missing"}, follow_redirects=False)
    assert r.status_code == 302
    import database
    from sqlmodel import Session, select
    with Session(database.engine) as s:
        subs = {x.url.rsplit("/", 1)[1]: x.id for x in s.exec(select(database.Subscription)).all()}
    assert set(subs) == {"sub1", "sub2", "missing"}

    # reserved webhook path is refused
    r = c.post("/ratings/save", data=_form("bad", "api", [subs["sub1"]]), follow_redirects=False)
    assert "error=" in r.headers["location"]

    # group A: sub1+sub2+missing; group B: sub2 only, vless/trojan only
    assert c.post("/ratings/save", data=_form("A", "hook-a", subs.values()), follow_redirects=False).status_code == 302
    form_b = _form("B", "hook-b", [subs["sub2"]])
    for p in ("vmess", "ss", "hy2", "hysteria2", "tuic", "hysteria", "anytls", "socks"):
        form_b.pop(f"proto_{p}")
    assert c.post("/ratings/save", data=form_b, follow_redirects=False).status_code == 302
    assert _wait(lambda: _groups()["A"].pool_size == 15 and _groups()["B"].pool_size == 5), \
        {n: (g.pool_size, g.last_fetch_status) for n, g in _groups().items()}
    a, b = _groups()["A"], _groups()["B"]
    with Session(database.engine) as s:
        missing = s.get(database.Subscription, subs["missing"])
        assert missing.last_fetch_ok is False and "404" in missing.last_error

    # a v2 node joins both groups
    nid = c.post("/api/node/register", json={"name": "n1", "region": "ru", "instance_id": "i1", "protocol": 2},
                 headers=H).json()["node_id"]
    for g in (a, b):
        c.post(f"/ratings/{g.id}/add-node/{nid}", follow_redirects=False)
    jobs = c.get(f"/api/node/jobs?node_id={nid}", headers=H).json()
    assert [j["due"] for j in jobs["jobs"]] == [True, True]
    job_a = next(j for j in jobs["jobs"] if j["group_id"] == a.id)
    assert job_a["chunk_size"] == 4 and jobs["test_urls"][0]["url"] == "https://example.com/"

    # group A: first chunk, then a restart: the remaining list shrinks (resume)
    lst = c.get(f"/api/node/groups/{a.id}/proxies?node_id={nid}", headers=H).json()
    assert lst["remaining"] == 15
    from_1 = [u for u in lst["proxies"] if u in SUB1]
    from_2 = [u for u in lst["proxies"] if u in SUB2]
    chunk = from_1[:2] + from_2[:2]   # 3 pass (incl. sub1 ones), the last fails
    res = [{"raw_url": u, "ping_ms": 50, "tests_passed": 1, "tests_total": 1} for u in chunk[:3]] + \
          [{"raw_url": chunk[3], "ping_ms": 0, "tests_passed": 0, "tests_total": 1}]
    out = c.post(f"/api/node/groups/{a.id}/results", json={"node_id": nid, "generation": lst["generation"],
                                                             "results": res}, headers=H).json()
    assert out["accepted"] == 4 and out["passed"] == 3 and not out["stale"]
    lst2 = c.get(f"/api/node/groups/{a.id}/proxies?node_id={nid}", headers=H).json()
    assert lst2["remaining"] == 11 and not set(chunk) & set(lst2["proxies"])
    rest = [{"raw_url": u, "ping_ms": 0, "tests_passed": 0, "tests_total": 1} for u in lst2["proxies"]]
    c.post(f"/api/node/groups/{a.id}/results", json={"node_id": nid, "generation": lst["generation"],
                                                      "results": rest}, headers=H)
    c.post(f"/api/node/groups/{a.id}/status", json={"node_id": nid, "generation": lst["generation"],
                                                     "status": "idle"}, headers=H)
    jobs = {j["group_id"]: j for j in c.get(f"/api/node/jobs?node_id={nid}", headers=H).json()["jobs"]}
    assert jobs[a.id]["due"] is False and jobs[b.id]["due"] is True

    # webhooks are independent: A has 3 proxies, B (untested) none
    import rating
    rating.invalidate_all()
    hook_a = c.get("/hook-a").text.splitlines()
    assert sorted(u.split("#")[0] for u in hook_a) == sorted(u.split("#")[0] for u in chunk[:3])
    assert c.get("/hook-b").text == ""
    assert c.get("/no-such-hook").status_code == 404

    # bans: the failing proxy fails again → banned for this node (threshold 2)
    c.post(f"/api/node/{nid}/force-test")
    lst3 = c.get(f"/api/node/groups/{a.id}/proxies?node_id={nid}", headers=H).json()
    assert lst3["generation"] != lst["generation"] and lst3["remaining"] == 15
    c.post(f"/api/node/groups/{a.id}/results", json={"node_id": nid, "generation": lst3["generation"],
           "results": [{"raw_url": chunk[3], "ping_ms": 0, "tests_passed": 0, "tests_total": 1}]}, headers=H)
    c.post(f"/api/node/{nid}/force-test")
    lst4 = c.get(f"/api/node/groups/{a.id}/proxies?node_id={nid}", headers=H).json()
    assert chunk[3] not in lst4["proxies"] and lst4["remaining"] == 14

    # retention: sub1 loses a passing proxy; after a refetch the node still gets it
    passing_from_sub1 = next(u for u in chunk[:3] if u in SUB1)
    CONTENT["/sub1"] = "\n".join(u for u in SUB1 if u != passing_from_sub1)
    gen_before = _groups()["A"].generation_id
    c.post(f"/ratings/{a.id}/fetch", follow_redirects=False)
    assert _wait(lambda: _groups()["A"].generation_id != gen_before)
    assert _groups()["A"].pool_size == 14
    lst5 = c.get(f"/api/node/groups/{a.id}/proxies?node_id={nid}", headers=H).json()
    assert passing_from_sub1 in lst5["proxies"]

    # a source that fails keeps its snapshot
    CONTENT.pop("/sub2")
    gen_before = _groups()["B"].generation_id
    c.post(f"/ratings/{b.id}/fetch", follow_redirects=False)
    assert _wait(lambda: _groups()["B"].generation_id != gen_before)
    assert _groups()["B"].pool_size == 5

    # legacy worker on group B only
    old = c.post("/api/node/register", json={"name": "old", "region": "x"}, headers=H).json()["node_id"]
    c.post(f"/ratings/{b.id}/add-node/{old}", follow_redirects=False)
    cfg = c.get(f"/api/node/config?node_id={old}", headers=H).json()
    assert cfg["generation_id"] and cfg["chunk_size"] == 4
    st = c.get(f"/api/node/state?node_id={old}", headers=H).json()
    assert st["status"] == "new"
    plist = c.get(f"/api/node/proxies?full=true&node_id={old}", headers=H).json()
    assert plist["total"] == 5 and all(u.startswith("trojan://") for u in plist["proxies"])
    c.post("/api/node/results", json={"node_id": old, "generation_id": cfg["generation_id"], "is_partial": True,
           "results": [{"raw_url": u, "ping_ms": 30, "tests_passed": 1, "tests_total": 1} for u in plist["proxies"][:2]]},
           headers=H)
    c.post("/api/node/status", json={"node_id": old, "status": "idle", "current_chunk": 1, "total_chunks": 1,
                                     "generation_id": cfg["generation_id"]}, headers=H)
    st = c.get(f"/api/node/state?node_id={old}", headers=H).json()
    assert st["status"] == "idle" and st["testing_generation_id"] == cfg["generation_id"]
    rating.invalidate_all()
    assert len(c.get("/hook-b").text.splitlines()) == 2
    assert len(c.get("/hook-a").text.splitlines()) == 3  # untouched by group B traffic

    # duplicate instance is rejected, same instance is accepted
    assert c.post("/api/node/register", json={"name": "n1", "instance_id": "other", "protocol": 2},
                  headers=H).json()["status"] == "already_active"
    assert c.post("/api/node/register", json={"name": "n1", "instance_id": "i1", "protocol": 2},
                  headers=H).json()["status"] == "updated"

    # pages render; protected APIs need a session; node API needs the token
    for page in ("/", "/subscriptions", "/ratings", "/nodes", "/settings", "/logs", "/test-urls",
                 f"/ratings/{a.id}/proxies"):
        r = c.get(page)
        assert r.status_code == 200, page
    assert "hook-a" in c.get("/ratings").text
    assert c.get("/api/node/jobs?node_id=1").status_code == 401
    from fastapi.testclient import TestClient
    import main
    anon = TestClient(main.app)
    assert anon.get("/api/logs").status_code == 401
    assert anon.get("/api/fetch-status").status_code == 401
    assert anon.get("/ratings", follow_redirects=False).status_code == 302

    # group deletion cascades
    c.post(f"/ratings/delete/{b.id}", follow_redirects=False)
    with Session(database.engine) as s:
        from sqlalchemy import text
        left = s.exec(text("SELECT COUNT(*) FROM group_node_proxies WHERE group_id = :g").bindparams(g=b.id)).one()[0]
    assert left == 0
    assert c.get("/hook-b").status_code == 404
