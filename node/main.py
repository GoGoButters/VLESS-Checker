import asyncio
import logging
import os
import sys
import httpx
import threading
from datetime import datetime, timezone

# Add parent dir to path to import proxy_parsers and tester logic
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import config after path setup
try:
    from config import config
except ImportError:
    print("CRITICAL: Could not import config. Check if node/config.py exists.", file=sys.stderr, flush=True)
    sys.exit(1)

# Configure logging IMMEDIATELY to catch early issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    force=True,
    stream=sys.stdout
)
# Ensure stdout is flushed on every log
for handler in logging.root.handlers:
    if hasattr(handler, 'stream') and handler.stream == sys.stdout:
        handler.flush = lambda: sys.stdout.flush()

logger = logging.getLogger("vpn_checker_node")

class RemoteLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.logs = []
        self._buffer_lock = threading.Lock()

    def emit(self, record):
        try:
            msg = self.format(record)
            entry = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "level": record.levelname,
                "message": msg,
            }
            with self._buffer_lock:
                self.logs.append(entry)
                if len(self.logs) > 1000:
                    self.logs = self.logs[-1000:]
        except Exception as e:
            print(f"ERROR in RemoteLogHandler.emit: {e}", file=sys.stderr, flush=True)

    def pop_all(self):
        try:
            with self._buffer_lock:
                logs = self.logs[:]
                self.logs.clear()
                return logs
        except Exception as e:
            print(f"ERROR in RemoteLogHandler.pop_all: {e}", file=sys.stderr, flush=True)
            return []

remote_log_handler = RemoteLogHandler()
logger.addHandler(remote_log_handler)
logging.getLogger("vpn_checker").addHandler(remote_log_handler)

class NodeApp:
    def __init__(self):
        self.master_url = config.master_url.rstrip("/")
        self.node_id = None
        self.last_run_id = None  # Track the master's proxy list version
        self.http_client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {config.node_token}"},
            timeout=30.0
        )
        logger.info(f"NodeApp initialized. Master URL: {self.master_url}")

    async def register(self) -> bool:
        try:
            payload = {
                "name": config.node_name,
                "region": config.node_region
            }
            logger.info(f"Registering with master at {self.master_url}...")
            resp = await self.http_client.post(f"{self.master_url}/api/node/register", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                self.node_id = data.get("node_id")
                logger.info(f"Registered successfully! Node ID: {self.node_id}")
                return True
            else:
                logger.error(f"Registration failed: HTTP {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error registering node: {e}")
            return False

    async def get_test_config(self):
        try:
            resp = await self.http_client.get(f"{self.master_url}/api/node/config")
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error(f"Error fetching config: {e}")
            return None

    async def get_proxies(self):
        """Fetch raw proxies and run_id from master. Returns (run_id, proxy_list)."""
        try:
            resp = await self.http_client.get(f"{self.master_url}/api/node/proxies")
            if resp.status_code == 200:
                data = resp.json()
                run_id = data.get("run_id", "unknown")
                proxies = data.get("proxies", [])
                return run_id, proxies
            return None, []
        except Exception as e:
            logger.error(f"Error fetching proxies: {e}")
            return None, []

    async def report_results(self, results, checked_count: int = 0):
        if not self.node_id:
            return False
            
        try:
            resp = await self.http_client.post(f"{self.master_url}/api/node/results", json={
                "node_id": self.node_id,
                "results": results,
                "checked_count": checked_count
            })
            if resp.status_code == 200:
                logger.info(f"Successfully reported {len(results)} results (out of {checked_count} checked) to master.")
                return True
            else:
                logger.error(f"Failed to report results: HTTP {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error reporting results: {e}")
            return False

    async def run_testing_cycle(self):
        # 1. Get test config from master
        test_config = await self.get_test_config()
        if not test_config:
            logger.warning("Could not fetch test config, skipping cycle.")
            return

        # Build test URL dicts
        test_urls = []
        for u in test_config.get("test_urls", []):
            test_urls.append({
                "url": u["url"],
                "expect_status": u["expect_status"],
                "min_body_bytes": u["min_body_bytes"]
            })

        ping_thresh = test_config.get("ping_threshold_ms", 1500)
        http_timeout = test_config.get("http_timeout_s", 10)
        concurrent = test_config.get("concurrent_checks_limit", config.concurrent_checks)
        speed_top_n = test_config.get("speed_test_top_n", 0)
        schedule_interval = test_config.get("schedule_interval_minutes", 0)

        run_id, raw_urls = await self.get_proxies()
        logger.info(f"Fetched proxies: run_id={run_id}, last_run_id={self.last_run_id}, count={len(raw_urls)}, schedule_interval={schedule_interval}min")
        if not raw_urls:
            logger.info("No proxies available from master. Idling.")
            return

        if run_id == self.last_run_id:
            logger.info(f"Proxies (run_id={run_id}) haven't changed since last test. Skipping cycle.")
            return

        logger.info(f"Starting tests with {len(raw_urls)} proxies (run_id={run_id})...")

        # 3. Test proxies using run_proxy_checks
        from tester import run_proxy_checks

        status_dict = {
            "running": True,
            "current_phase": "checking",
            "checked": 0,
            "total": len(raw_urls),
            "passed": 0,
            "failed": 0,
        }

        valid_proxies = await run_proxy_checks(
            raw_urls, test_urls, ping_thresh, http_timeout, concurrent, status_dict,
            singbox_path=config.singbox_path,
        )

        logger.info(f"Proxy checks done: {status_dict['passed']} passed, {status_dict['failed']} failed out of {status_dict['checked']} checked.")

        # 4. Build results for ALL tested proxies (passed + failed)
        # We need to report failures too so the master can evaluate bans across all nodes
        all_tested_results = []
        passed_urls = set()
        
        for p in valid_proxies:
            passed_urls.add(p.raw_url)
            all_tested_results.append({
                "raw_url": p.raw_url,
                "ping_ms": p.ping_ms,
                "tests_passed": p.tests_passed,
                "tests_total": p.tests_total,
                "download_speed_kbps": getattr(p, "download_speed_kbps", 0),
                "upload_speed_kbps": getattr(p, "upload_speed_kbps", 0),
                "speed_score": getattr(p, "speed_score", 0.0),
            })
        
        # Add failed proxies (those that were tested but didn't pass)
        for url in raw_urls:
            if url not in passed_urls:
                all_tested_results.append({
                    "raw_url": url,
                    "ping_ms": 0,
                    "tests_passed": 0,
                    "tests_total": len(test_urls),
                    "download_speed_kbps": 0,
                    "upload_speed_kbps": 0,
                    "speed_score": 0.0,
                })

        # 5. Optional: Speed testing phase
        if speed_top_n > 0 and valid_proxies:
            from speed_tester import _measure_speed, _compute_speed_score
            logger.info(f"Running speed tests for top {min(speed_top_n, len(valid_proxies))} proxies (multi-stream)...")

            to_test = sorted(valid_proxies, key=lambda p: (-p.tests_passed, p.ping_ms))[:speed_top_n]
            speed_sem = asyncio.Semaphore(2)  # 2 concurrent speed tests (each uses 4 streams)

            async def _speed_one(p):
                async with speed_sem:
                    result = await _measure_speed(p.raw_url, timeout_s=max(http_timeout + 10, 20))
                    if result:
                        dl, ul = result
                        p.download_speed_kbps = dl
                        p.upload_speed_kbps = ul
                        p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, dl, ul)
                        logger.info(f"⚡ Speed [{p.ping_ms}ms] DL={dl}KB/s UL={ul}KB/s Score={p.speed_score:.0f}")
                        # Update the result in all_tested_results
                        for r in all_tested_results:
                            if r["raw_url"] == p.raw_url:
                                r["download_speed_kbps"] = dl
                                r["upload_speed_kbps"] = ul
                                r["speed_score"] = p.speed_score
                                break
                    else:
                        p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, 0, 0)

            await asyncio.gather(*[_speed_one(p) for p in to_test])

        # 6. Report ALL results (passed + failed) and save run_id
        reported = await self.report_results(all_tested_results, checked_count=status_dict["checked"])
        if reported:
            self.last_run_id = run_id
            logger.info(f"Saved run_id={run_id}. Will idle until master produces a new proxy list.")

    async def log_sender_loop(self):
        while True:
            await asyncio.sleep(5)
            logs = remote_log_handler.pop_all()
            if not logs:
                continue
            if not self.node_id:
                # Put them back if not registered
                with remote_log_handler._buffer_lock:
                    remote_log_handler.logs = logs + remote_log_handler.logs
                    if len(remote_log_handler.logs) > 1000:
                        remote_log_handler.logs = remote_log_handler.logs[-1000:]
                continue
            try:
                resp = await self.http_client.post(
                    f"{self.master_url}/api/node/logs",
                    json={"node_id": self.node_id, "logs": logs}
                )
                if resp.status_code != 200:
                    with remote_log_handler._buffer_lock:
                        remote_log_handler.logs = logs + remote_log_handler.logs
                        if len(remote_log_handler.logs) > 1000:
                            remote_log_handler.logs = remote_log_handler.logs[-1000:]
            except Exception as e:
                with remote_log_handler._buffer_lock:
                    remote_log_handler.logs = logs + remote_log_handler.logs
                    if len(remote_log_handler.logs) > 1000:
                        remote_log_handler.logs = remote_log_handler.logs[-1000:]



async def main():
    logger.info("Initializing VPN Checker Worker Node...")
    app = NodeApp()
    
    # Start the log sender loop in the background
    asyncio.create_task(app.log_sender_loop())
    
    while True:
        try:
            logger.debug("Waking up for check-in...")
            # Always register/re-register to keep heartbeat alive
            await app.register()
                
            if app.node_id:
                await app.run_testing_cycle()
                
        except Exception as e:
            logger.error(f"Unhandled error in main loop: {e}")
            
        logger.debug(f"Sleeping for {config.poll_interval_s} seconds...")
        await asyncio.sleep(config.poll_interval_s)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Node shut down by user.")
    except Exception as e:
        logger.critical(f"Critical error during startup: {e}", exc_info=True)
        sys.exit(1)
