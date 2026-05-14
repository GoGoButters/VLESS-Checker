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
            print(f"ERROR in RemoteLogHandler.emit: {repr(e)}", file=sys.stderr, flush=True)

    def pop_all(self):
        try:
            with self._buffer_lock:
                logs = self.logs[:]
                self.logs.clear()
                return logs
        except Exception as e:
            print(f"ERROR in RemoteLogHandler.pop_all: {repr(e)}", file=sys.stderr, flush=True)
            return []

remote_log_handler = RemoteLogHandler()
logger.addHandler(remote_log_handler)
logging.getLogger("vpn_checker").addHandler(remote_log_handler)

class NodeApp:
    def __init__(self):
        self.master_url = config.master_url.rstrip("/")
        self.node_id = None
        self.last_run_id = None  # Track the master's proxy list version
        self.last_test_completed_at = None  # When the last test cycle finished
        self.last_schedule_interval = 0  # Last known schedule interval from master
        self.chunk_size = 0  # Chunk size from master (0 = disabled)
        self.generation_id = None  # Current generation_id from master
        self.last_generation_id = None  # Previous generation_id (to detect new cycle)
        self.chunk_offset = 0  # Current offset for chunked requests
        self.http_client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {config.node_token}"},
            timeout=30.0
        )
        self._heartbeat_task = None  # Background heartbeat task
        logger.info(f"NodeApp initialized. Master URL: {self.master_url}")

    def _should_wait_for_schedule(self) -> bool:
        """Check if we should still wait before running the next test cycle.
        Returns True if the schedule interval hasn't elapsed yet."""
        if self.last_test_completed_at is None:
            return False  # Never tested, run immediately
        if self.last_schedule_interval <= 0:
            return False  # No interval configured, poll freely

        elapsed = (datetime.now(timezone.utc) - self.last_test_completed_at).total_seconds()
        remaining = (self.last_schedule_interval * 60) - elapsed
        if remaining > 0:
            return True
        return False

    def _get_remaining_wait_seconds(self) -> float:
        """Get seconds remaining until the schedule interval elapses."""
        if self.last_test_completed_at is None or self.last_schedule_interval <= 0:
            return 0
        elapsed = (datetime.now(timezone.utc) - self.last_test_completed_at).total_seconds()
        remaining = (self.last_schedule_interval * 60) - elapsed
        return max(0, remaining)

    async def _heartbeat_loop(self):
        """Background loop: send heartbeat to master every 30 seconds."""
        logger.info("Heartbeat loop started")
        while True:
            await asyncio.sleep(30)
            if self.node_id is None:
                # Not registered yet, skip heartbeat
                continue
            try:
                resp = await self.http_client.post(
                    f"{self.master_url}/api/node/heartbeat",
                    json={"node_id": self.node_id}
                )
                if resp.status_code == 200:
                    logger.debug(f"Heartbeat sent for node {self.node_id}")
                else:
                    logger.warning(f"Heartbeat failed: HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"Heartbeat error: {repr(e)}")

    async def register(self) -> bool:
        """Register with master, with exponential backoff retry on connection errors."""
        import httpx
        
        max_retries = 3
        base_delay = 2.0  # seconds
        
        last_error = None
        for attempt in range(max_retries):
            try:
                payload = {
                    "name": config.node_name,
                    "region": config.node_region
                }
                if attempt == 0:
                    logger.info(f"Registering with master at {self.master_url}...")
                else:
                    logger.info(f"Register attempt {attempt + 1}/{max_retries}...")
                
                resp = await self.http_client.post(f"{self.master_url}/api/node/register", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    self.node_id = data.get("node_id")
                    logger.info(f"Registered successfully! Node ID: {self.node_id}")
                    return True
                else:
                    logger.error(f"Registration failed: HTTP {resp.status_code} - {resp.text}")
                    # Non-connection errors - don't retry
                    return False
                    
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as e:
                last_error = e
                logger.warning(f"Connection error on attempt {attempt + 1}/{max_retries}: {repr(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)  # 2, 4, 8 seconds
                    logger.info(f"Retrying in {delay:.1f} seconds...")
                    await asyncio.sleep(delay)
            except Exception as e:
                last_error = e
                logger.error(f"Error registering node: {repr(e)}")
                # Other errors - don't retry
                return False
        
        logger.error(f"Failed to register after {max_retries} attempts: {repr(last_error)}")
        return False

    async def get_test_config(self):
        try:
            resp = await self.http_client.get(f"{self.master_url}/api/node/config")
            if resp.status_code == 200:
                data = resp.json()
                # Store chunk_size and generation_id for chunking logic
                self.chunk_size = data.get("chunk_size", 0)
                self.generation_id = data.get("generation_id")
                return data
            return None
        except Exception as e:
            logger.error(f"Error fetching config: {repr(e)}")
            return None

    async def get_proxies(self, offset: int = 0, limit: int = 0):
        """Fetch raw proxies and run_id from master. Returns (run_id, proxy_list, has_more, total)."""
        try:
            params = {}
            if offset > 0:
                params["offset"] = offset
            if limit > 0:
                params["limit"] = limit
            resp = await self.http_client.get(f"{self.master_url}/api/node/proxies", params=params if params else None)
            if resp.status_code == 200:
                data = resp.json()
                run_id = data.get("run_id", "unknown")
                proxies = data.get("proxies", [])
                has_more = data.get("has_more", False)
                total = data.get("total", 0)
                return run_id, proxies, has_more, total
            return None, [], False, 0
        except Exception as e:
            logger.error(f"Error fetching proxies: {repr(e)}")
            return None, [], False, 0

    async def report_results(self, results, checked_count: int = 0, is_partial: bool = False):
        if not self.node_id:
            return False

        try:
            resp = await self.http_client.post(f"{self.master_url}/api/node/results", json={
                "node_id": self.node_id,
                "results": results,
                "checked_count": checked_count,
                "is_partial": is_partial
            })
            if resp.status_code == 200:
                logger.info(f"Successfully reported {len(results)} results (out of {checked_count} checked) to master. is_partial={is_partial}")
                return True
            else:
                logger.error(f"Failed to report results: HTTP {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error reporting results: {repr(e)}")
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

        # Update the known schedule interval from master
        self.last_schedule_interval = schedule_interval

        # Check if we should wait before running next cycle
        if self._should_wait_for_schedule():
            remaining = self._get_remaining_wait_seconds()
            remaining_min = remaining / 60
            logger.info(f"Schedule interval not elapsed yet. Next test in {remaining_min:.0f}min. Skipping cycle.")
            return

        # Check if generation_id changed (new scheduler cycle) - reset chunk offset
        if self.generation_id and self.generation_id != self.last_generation_id:
            logger.info(f"New generation detected: {self.generation_id} (previous: {self.last_generation_id}). Resetting chunk offset.")
            self.last_run_id = None  # Reset run_id cache to force re-check
            self.chunk_offset = 0
            self.last_generation_id = self.generation_id

        # Use chunking if enabled (chunk_size > 0)
        if self.chunk_size > 0:
            await self._run_chunked_testing(test_urls, ping_thresh, http_timeout, concurrent, speed_top_n, schedule_interval)
        else:
            # Original non-chunked behavior
            await self._run_full_testing(test_urls, ping_thresh, http_timeout, concurrent, speed_top_n, schedule_interval)

        # Update last test completion time
        self.last_test_completed_at = datetime.now(timezone.utc)

    async def _run_chunked_testing(self, test_urls, ping_thresh, http_timeout, concurrent, speed_top_n, schedule_interval):
        """Run testing in chunks for dynamic rating updates."""
        from tester import run_proxy_checks
        from speed_tester import _measure_speed, _compute_speed_score

        total_proxies_checked = 0
        total_proxies_passed = 0

        while True:
            # Fetch current chunk
            run_id, raw_urls, has_more, total = await self.get_proxies(offset=self.chunk_offset, limit=self.chunk_size)
            logger.info(f"Chunk {self.chunk_offset // self.chunk_size + 1}: offset={self.chunk_offset}, count={len(raw_urls)}, has_more={has_more}, total={total}")

            if not raw_urls:
                logger.info(f"No more proxies to check at offset {self.chunk_offset}. Chunking complete.")
                break

            # Skip if run_id hasn't changed (same proxies already tested in this generation)
            if run_id == self.last_run_id:
                logger.info(f"Proxies (run_id={run_id}) already tested in this generation. Skipping chunk.")
                self.chunk_offset += len(raw_urls)
                if not has_more:
                    break
                continue

            logger.info(f"Testing {len(raw_urls)} proxies in chunk (run_id={run_id})...")

            # Test proxies in this chunk
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

            total_proxies_checked += status_dict["checked"]
            total_proxies_passed += status_dict["passed"]
            logger.info(f"Chunk results: {status_dict['passed']} passed, {status_dict['failed']} failed")

            # Build results for all tested proxies
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

            # Compute baseline speed scores
            for r in all_tested_results:
                r["speed_score"] = _compute_speed_score(
                    r["ping_ms"], r["tests_passed"], r["download_speed_kbps"], r["upload_speed_kbps"]
                )

            # Optional speed testing for top N proxies in chunk
            if speed_top_n > 0 and valid_proxies:
                to_test = sorted(valid_proxies, key=lambda p: (-p.tests_passed, p.ping_ms))[:speed_top_n]
                chunk_total = len(valid_proxies)
                speed_sem = asyncio.Semaphore(2)
                counter_lock = asyncio.Lock()
                done = 0

                logger.info(f"Running speed tests for top {len(to_test)} proxies in chunk...")

                async def _speed_one(p):
                    nonlocal done
                    async with speed_sem:
                        result = await _measure_speed(p.raw_url, timeout_s=max(http_timeout + 10, 20))
                        if result:
                            dl, ul = result
                            p.download_speed_kbps = dl
                            p.upload_speed_kbps = ul
                            p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, dl, ul)
                            async with counter_lock:
                                done += 1
                                logger.info(f"⚡ Speed [{p.ping_ms}ms] DL={dl}KB/s UL={ul}KB/s Score={p.speed_score:.0f} ({done}/{chunk_total})")
                            for r in all_tested_results:
                                if r["raw_url"] == p.raw_url:
                                    r["download_speed_kbps"] = dl
                                    r["upload_speed_kbps"] = ul
                                    r["speed_score"] = p.speed_score
                                    break
                        else:
                            p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, 0, 0)
                            async with counter_lock:
                                done += 1

                await asyncio.gather(*[_speed_one(p) for p in to_test])

            # Report results as partial (upsert instead of full replace)
            reported = await self.report_results(all_tested_results, checked_count=status_dict["checked"], is_partial=True)
            if reported:
                logger.info(f"Reported chunk results (is_partial=True). Offset now at {self.chunk_offset + len(raw_urls)}")
            else:
                logger.warning(f"Failed to report chunk results, but continuing to next chunk.")

            # Update run_id after successfully testing this chunk
            self.last_run_id = run_id

            # Move to next chunk
            self.chunk_offset += len(raw_urls)

            if not has_more:
                logger.info(f"All chunks processed. Total: {total_proxies_checked} checked, {total_proxies_passed} passed.")
                break

        # Final status
        next_in = f" Next test in ~{schedule_interval}min." if schedule_interval > 0 else ""
        logger.info(f"Chunked testing complete. Checked {total_proxies_checked}, passed {total_proxies_passed}.{next_in}")

    async def _run_full_testing(self, test_urls, ping_thresh, http_timeout, concurrent, speed_top_n, schedule_interval):
        """Original non-chunked testing logic."""
        from tester import run_proxy_checks
        from speed_tester import _measure_speed, _compute_speed_score

        run_id, raw_urls, has_more, total = await self.get_proxies()
        logger.info(f"Fetched proxies: run_id={run_id}, last_run_id={self.last_run_id}, count={len(raw_urls)}, schedule_interval={schedule_interval}min")
        if not raw_urls:
            logger.info("No proxies available from master. Idling.")
            return

        if run_id == self.last_run_id:
            logger.info(f"Proxies (run_id={run_id}) haven't changed since last test. Skipping cycle.")
            return

        logger.info(f"Starting tests with {len(raw_urls)} proxies (run_id={run_id})...")

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

        for r in all_tested_results:
            r["speed_score"] = _compute_speed_score(
                r["ping_ms"], r["tests_passed"], r["download_speed_kbps"], r["upload_speed_kbps"]
            )

        if speed_top_n > 0 and valid_proxies:
            to_test = sorted(valid_proxies, key=lambda p: (-p.tests_passed, p.ping_ms))[:speed_top_n]
            total = len(valid_proxies)
            speed_sem = asyncio.Semaphore(2)
            counter_lock = asyncio.Lock()
            done = 0

            logger.info(f"Running speed tests for top {len(to_test)} proxies (multi-stream, total={total})...")

            async def _speed_one(p):
                nonlocal done
                async with speed_sem:
                    result = await _measure_speed(p.raw_url, timeout_s=max(http_timeout + 10, 20))
                    if result:
                        dl, ul = result
                        p.download_speed_kbps = dl
                        p.upload_speed_kbps = ul
                        p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, dl, ul)
                        async with counter_lock:
                            done += 1
                            logger.info(f"⚡ Speed [{p.ping_ms}ms] DL={dl}KB/s UL={ul}KB/s Score={p.speed_score:.0f} ({done}/{total})")
                        for r in all_tested_results:
                            if r["raw_url"] == p.raw_url:
                                r["download_speed_kbps"] = dl
                                r["upload_speed_kbps"] = ul
                                r["speed_score"] = p.speed_score
                                break
                    else:
                        p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, 0, 0)
                        async with counter_lock:
                            done += 1

            await asyncio.gather(*[_speed_one(p) for p in to_test])

        self.last_run_id = run_id
        reported = await self.report_results(all_tested_results, checked_count=status_dict["checked"], is_partial=False)
        if reported:
            next_in = f" Next test in ~{schedule_interval}min." if schedule_interval > 0 else ""
            logger.info(f"Saved run_id={run_id}. Will idle until master produces a new proxy list.{next_in}")
        else:
            logger.warning(f"Failed to report results for run_id={run_id}, but saved run_id to avoid immediate re-testing.")

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
                    print(f"WARNING: Log delivery failed: HTTP {resp.status_code} - {resp.text[:200]}", file=sys.stderr, flush=True)
                    with remote_log_handler._buffer_lock:
                        remote_log_handler.logs = logs + remote_log_handler.logs
                        if len(remote_log_handler.logs) > 1000:
                            remote_log_handler.logs = remote_log_handler.logs[-1000:]
            except Exception as e:
                print(f"WARNING: Log delivery error: {repr(e)}", file=sys.stderr, flush=True)
                with remote_log_handler._buffer_lock:
                    remote_log_handler.logs = logs + remote_log_handler.logs
                    if len(remote_log_handler.logs) > 1000:
                        remote_log_handler.logs = remote_log_handler.logs[-1000:]



async def main():
    logger.info("Initializing VPN Checker Worker Node...")
    app = NodeApp()
    
    # Start the log sender loop in the background
    app._log_task = asyncio.create_task(app.log_sender_loop())
    
    # Start the heartbeat loop in the background (keeps node online during testing)
    app._heartbeat_task = asyncio.create_task(app._heartbeat_loop())
    
    while True:
        try:
            logger.debug("Waking up for check-in...")
            # Always register/re-register to keep heartbeat alive
            await app.register()
                
            if app.node_id:
                await app.run_testing_cycle()
                
        except Exception as e:
            logger.error(f"Unhandled error in main loop: {repr(e)}")
            
        # Use schedule-aware sleep: if we know the schedule interval,
        # sleep in chunks but don't exceed the remaining wait time
        remaining = app._get_remaining_wait_seconds()
        if remaining > 0:
            # Sleep in chunks of poll_interval_s to stay responsive to heartbeats
            sleep_time = min(config.poll_interval_s, remaining)
            logger.debug(f"Schedule wait: {remaining:.0f}s remaining, sleeping {sleep_time:.0f}s...")
        else:
            sleep_time = config.poll_interval_s
            logger.debug(f"Sleeping for {sleep_time} seconds...")
        await asyncio.sleep(sleep_time)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Node shut down by user.")
    except Exception as e:
        logger.critical(f"Critical error during startup: {repr(e)}", exc_info=True)
        sys.exit(1)
