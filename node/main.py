"""VPN Checker worker node.

Loop: ask the panel for jobs (one per rating group of this node), test the
remaining proxies of each due group chunk by chunk, post results after every
chunk, report idle at the end. The panel remembers what was already tested in
the current generation, so after a restart the node simply continues.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
import uuid
from collections import deque
from datetime import datetime, timezone

import httpx

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                    stream=sys.stdout, force=True)
logger = logging.getLogger("vpn_checker_node")

LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40, "off": 999}
# xhttp / splithttp / httpupgrade most often get through CDNs and whitelists: test them first.
PRIORITY_MARKERS = ("type=xhttp", "type=splithttp", "type=httpupgrade")
RESULT_POST_ATTEMPTS = 8
POST_BATCH = 2000  # the panel accepts up to 5000 results per request


class RemoteLogHandler(logging.Handler):
    """Buffers log records for delivery to the panel (bounded, drops oldest)."""

    def __init__(self):
        super().__init__()
        self.buffer: deque = deque(maxlen=1000)
        self._buf_lock = threading.Lock()
        self.min_level = 20

    def emit(self, record):
        if record.levelno < self.min_level:
            return
        try:
            entry = {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                     "level": record.levelname, "message": self.format(record)}
        except Exception:
            return
        with self._buf_lock:
            self.buffer.append(entry)

    def take(self) -> list[dict]:
        with self._buf_lock:
            items = list(self.buffer)
            self.buffer.clear()
            return items

    def put_back(self, items: list[dict]) -> None:
        with self._buf_lock:
            self.buffer.extendleft(reversed(items))


remote_logs = RemoteLogHandler()
for name in ("vpn_checker_node", "vpn_checker"):
    logging.getLogger(name).addHandler(remote_logs)


def sort_by_priority(urls: list[str]) -> list[str]:
    def rank(u: str) -> int:
        low = u.lower()
        return next((i for i, m in enumerate(PRIORITY_MARKERS) if m in low), len(PRIORITY_MARKERS))
    return sorted(urls, key=rank)


class Stale(Exception):
    """The group got a new generation while we were testing the old one."""


class NodeGone(Exception):
    """The panel no longer knows this node id (deleted) — register again."""


class Worker:
    def __init__(self):
        self.master = config.master_url.rstrip("/")
        self.node_id: int | None = None
        self.instance_id = uuid.uuid4().hex
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {config.node_token}"},
            timeout=httpx.Timeout(60.0, connect=10.0),
        )

    # ------------------------------------------------------------------ API
    async def _call(self, method: str, path: str, **kw) -> dict:
        resp = await self.client.request(method, f"{self.master}{path}", **kw)
        if resp.status_code == 404 and "Node not found" in resp.text:
            raise NodeGone()
        resp.raise_for_status()
        return resp.json()

    async def register(self) -> None:
        delay = 5
        while True:
            try:
                data = await self._call("POST", "/api/node/register", json={
                    "name": config.node_name, "region": config.node_region,
                    "instance_id": self.instance_id, "protocol": 2})
                if data.get("status") == "already_active":
                    logger.warning(f"Another instance named '{config.node_name}' is active; retrying later")
                else:
                    self.node_id = data["node_id"]
                    logger.info(f"Registered as node {self.node_id} ({data.get('status')})")
                    return
            except (httpx.HTTPError, KeyError, ValueError) as e:
                logger.warning(f"Register failed: {e!r}")
            await asyncio.sleep(delay)
            delay = min(delay * 2, config.poll_interval_s)

    async def post_results(self, gid: int, generation: str, results: list[dict]) -> None:
        """Deliver one chunk; retries transient failures, aborts the run when stale."""
        delay = 5.0
        for attempt in range(1, RESULT_POST_ATTEMPTS + 1):
            try:
                out = await self._call("POST", f"/api/node/groups/{gid}/results", json={
                    "node_id": self.node_id, "generation": generation, "results": results})
                if out.get("stale"):
                    raise Stale()
                return
            except httpx.HTTPStatusError as e:
                if e.response.status_code < 500 and e.response.status_code not in (408, 429):
                    raise  # a request the panel will never accept: do not loop on it
                err = e
            except httpx.HTTPError as e:
                err = e
            logger.warning(f"Posting results failed (attempt {attempt}): {err!r}")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 120)
        raise RuntimeError("panel unreachable, results of this chunk are lost (will be re-tested)")

    async def status(self, gid: int, generation: str, status: str, cur: int = 0, total: int = 0) -> None:
        try:
            await self._call("POST", f"/api/node/groups/{gid}/status", json={
                "node_id": self.node_id, "generation": generation, "status": status,
                "current_chunk": cur, "total_chunks": total})
        except httpx.HTTPError as e:
            logger.warning(f"Status report failed: {e!r}")

    # ------------------------------------------------------------ background
    async def heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            if self.node_id is None:
                continue
            try:
                await self._call("POST", "/api/node/heartbeat", json={"node_id": self.node_id})
            except NodeGone:
                logger.warning("Panel forgot this node; registering again")
                self.node_id = None
            except httpx.HTTPError as e:
                logger.warning(f"Heartbeat failed: {e!r}")

    async def log_loop(self) -> None:
        while True:
            await asyncio.sleep(5)
            if self.node_id is None or remote_logs.min_level >= LEVELS["off"]:
                continue
            items = remote_logs.take()
            if not items:
                continue
            try:
                await self._call("POST", "/api/node/logs", json={"node_id": self.node_id, "logs": items})
            except (httpx.HTTPError, NodeGone):
                remote_logs.put_back(items)

    # ---------------------------------------------------------------- testing
    async def run_group(self, job: dict, test_urls: list[dict], speed_url: str) -> None:
        from geo_checker import detect_proxy_country
        from speed_tester import compute_speed_score, measure_speed
        from tester import run_proxy_checks

        gid, gen = job["group_id"], job["generation"]
        data = await self._call("GET", f"/api/node/groups/{gid}/proxies", params={"node_id": self.node_id})
        if data.get("generation") != gen:
            return  # changed between /jobs and now; the next poll picks it up
        urls = sort_by_priority(data.get("proxies") or [])
        if not urls:
            await self.status(gid, gen, "idle")
            return
        size = job.get("chunk_size") or len(urls)
        chunks = [urls[i:i + size] for i in range(0, len(urls), size)]
        timeout = float(job.get("http_timeout_s") or 10)
        logger.info(f"[{job['name']}] {len(urls)} proxies to test (of {data.get('pool_total')}), "
                    f"{len(chunks)} chunk(s), generation {gen[:8]}")
        total_passed = 0
        for i, chunk in enumerate(chunks, start=1):
            await self.status(gid, gen, "testing", i, len(chunks))
            results = await run_proxy_checks(chunk, test_urls, job.get("ping_threshold_ms") or 1000, timeout,
                                             job.get("concurrent_checks_limit") or config.concurrent_checks)
            passing = [r for r in results if r["tests_passed"] > 0 and r["ping_ms"] > 0]
            total_passed += len(passing)

            top_n = job.get("speed_test_top_n") or 0
            if top_n and passing:
                sem = asyncio.Semaphore(2)

                async def speed(r: dict):
                    async with sem:
                        m = await measure_speed(r["raw_url"], timeout_s=max(timeout + 10, 20),
                                                extra_dl_urls=[speed_url] if speed_url else None)
                    if m:
                        r["download_speed_kbps"], r["upload_speed_kbps"] = m
                ranked = sorted(passing, key=lambda r: (-r["tests_passed"], r["ping_ms"]))[:top_n]
                await asyncio.gather(*(speed(r) for r in ranked))

            if job.get("geo_check_enabled") and passing:
                sem = asyncio.Semaphore(3)

                async def geo(r: dict):
                    async with sem:
                        r["country_name"] = await detect_proxy_country(r["raw_url"], timeout_s=max(timeout, 10))
                await asyncio.gather(*(geo(r) for r in passing))

            for r in results:
                r["speed_score"] = compute_speed_score(r["ping_ms"], r["tests_passed"],
                                                       r.get("download_speed_kbps", 0), r.get("upload_speed_kbps", 0))
            for j in range(0, len(results), POST_BATCH):
                await self.post_results(gid, gen, results[j:j + POST_BATCH])
            logger.info(f"[{job['name']}] chunk {i}/{len(chunks)}: {len(passing)}/{len(chunk)} passed")
        await self.status(gid, gen, "idle", len(chunks), len(chunks))
        logger.info(f"[{job['name']}] run complete: {total_passed}/{len(urls)} passed")

    async def run(self) -> None:
        asyncio.create_task(self.heartbeat_loop())
        asyncio.create_task(self.log_loop())
        while True:
            try:
                if self.node_id is None:
                    await self.register()
                jobs = await self._call("GET", "/api/node/jobs", params={"node_id": self.node_id})
                remote_logs.min_level = LEVELS.get(jobs.get("node_log_level", "info"), 20)
                due = [j for j in jobs.get("jobs", []) if j.get("due")]
                speed_url = f"{self.master}{jobs['speed_test_dl_url']}" if jobs.get("speed_test_dl_url") else ""
                if not jobs.get("jobs"):
                    logger.info("No rating group assigned — idle")
                for job in due:
                    try:
                        await self.run_group(job, jobs.get("test_urls") or [], speed_url)
                    except Stale:
                        logger.info(f"[{job['name']}] new generation started on the panel — switching")
                if due:
                    await asyncio.sleep(2)
                    continue  # look for more work right away
            except NodeGone:
                self.node_id = None
                continue
            except Exception as e:  # never die; never drop the registration on a transient error
                logger.error(f"Worker loop error: {e!r}")
            await asyncio.sleep(config.poll_interval_s)


async def main() -> None:
    logger.info(f"VPN Checker node '{config.node_name}' starting, panel {config.master_url}")
    if config.bind_interface:
        os.environ["BIND_INTERFACE"] = config.bind_interface
    await Worker().run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
