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
        self.last_test_completed_at = None  # When the last test cycle finished
        self.last_schedule_interval = 0  # Last known schedule interval from master
        self.chunk_size = 0  # Chunk size from master (0 = disabled)
        self.generation_id = None  # Current generation_id from master
        self.last_generation_id = None  # Previous generation_id (to detect new cycle)
        self.force_test = False  # Manual force-test trigger from master
        # Worker-side chunking state
        self.total_chunks = 0
        self.current_chunk = 0
        self._already_active = False  # set True when master reports duplicate
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
                    reg_status = data.get("status", "")
                    if reg_status == "already_active":
                        logger.warning(
                            f"Another instance of this node is already active (node_id={self.node_id}). "
                            f"Will wait and retry. This worker will NOT start testing."
                        )
                        self._already_active = True
                        self.node_id = None  # Don't register as active — we're a duplicate
                        return True  # registered but flagged as duplicate
                    logger.info(f"Registered successfully! Node ID: {self.node_id}")
                    self._already_active = False
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
            params = {}
            if self.node_id:
                params["node_id"] = self.node_id
            resp = await self.http_client.get(
                f"{self.master_url}/api/node/config",
                params=params
            )
            if resp.status_code == 200:
                data = resp.json()
                # Store chunk_size and generation_id for chunking logic
                self.chunk_size = data.get("chunk_size", 0)
                self.generation_id = data.get("generation_id")
                self.force_test = data.get("force_test", False)
                return data
            return None
        except Exception as e:
            logger.error(f"Error fetching config: {repr(e)}")
            return None

    async def get_all_proxies(self):
        """Fetch ALL proxies from master (full=true mode).
        Returns (run_id, proxy_list, total, chunk_size)."""
        try:
            resp = await self.http_client.get(
                f"{self.master_url}/api/node/proxies",
                params={"full": "true"}
            )
            if resp.status_code == 200:
                data = resp.json()
                run_id = data.get("run_id", "unknown")
                proxies = data.get("proxies", [])
                total = data.get("total", 0)
                chunk_size = data.get("chunk_size", 0)
                return run_id, proxies, total, chunk_size
            logger.error(f"get_all_proxies failed: HTTP {resp.status_code}")
            return None, [], 0, 0
        except Exception as e:
            logger.error(f"Error fetching all proxies: {repr(e)}")
            return None, [], 0, 0

    async def report_status(self, status: str, current_chunk: int, total_chunks: int, generation_id: str):
        """Report testing progress to master."""
        if not self.node_id:
            return False
        try:
            resp = await self.http_client.post(
                f"{self.master_url}/api/node/status",
                json={
                    "node_id": self.node_id,
                    "status": status,
                    "current_chunk": current_chunk,
                    "total_chunks": total_chunks,
                    "generation_id": generation_id,
                }
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Error reporting status: {repr(e)}")
            return False

    async def get_node_state(self):
        """Fetch current node state from master (for crash recovery)."""
        if not self.node_id:
            return None
        try:
            resp = await self.http_client.get(
                f"{self.master_url}/api/node/state",
                params={"node_id": self.node_id}
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error(f"Error fetching node state: {repr(e)}")
            return None

    async def report_results(self, results, checked_count: int = 0, is_partial: bool = False):
        if not self.node_id:
            return False

        try:
            resp = await self.http_client.post(f"{self.master_url}/api/node/results", json={
                "node_id": self.node_id,
                "results": results,
                "checked_count": checked_count,
                "is_partial": is_partial,
                "generation_id": self.generation_id
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
        # 1. Check if this worker is flagged as duplicate by master
        if self._already_active:
            logger.warning("Another instance is active. Skipping test cycle.")
            return

        # 2. Get test config from master
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

        # 3. Check if generation_id changed (new fetch cycle) - reset state BEFORE schedule check
        is_new_generation = (
            self.generation_id is not None and
            self.generation_id != self.last_generation_id
        )

        if is_new_generation:
            logger.info(f"New generation detected: {self.generation_id} "
                        f"(previous: {self.last_generation_id}). "
                        f"Resetting state and bypassing schedule wait.")
            self.last_generation_id = self.generation_id
            # Reset last_test_completed_at to bypass schedule wait
            self.last_test_completed_at = None

        # 4. Manual force-test trigger: bypass schedule wait
        if self.force_test:
            logger.info("Force test triggered by master. Bypassing schedule wait.")
            self.last_test_completed_at = None
            self.force_test = False

        # 5. Schedule guard: skip if interval hasn't elapsed (only for non-new generations, non-forced)
        if not is_new_generation and self._should_wait_for_schedule():
            remaining = self._get_remaining_wait_seconds()
            remaining_min = remaining / 60
            logger.info(f"Schedule interval not elapsed yet. Next test in {remaining_min:.0f}min. Skipping cycle.")
            return

        # 5. Crash recovery: check if we have a saved state on master
        start_chunk = 0
        if is_new_generation:
            state = await self.get_node_state()
            if state:
                master_status = state.get("status", "idle")
                master_gen = state.get("testing_generation_id", "")
                master_chunk = state.get("current_chunk", 0)
                master_chunks = state.get("total_chunks", 0)

                # Skip entirely if this generation was already completed.
                # The node has finished all chunks and is idle — no need to re-test.
                if (master_status == "idle" and
                    master_gen == self.generation_id and
                    master_chunks > 0):
                    logger.info(f"Generation {self.generation_id} already completed "
                               f"({master_chunks} chunks). Skipping test.")
                    self.last_generation_id = self.generation_id
                    self.last_test_completed_at = datetime.now(timezone.utc)
                    return

                # Resume if generation was in progress and not yet finished.
                if (master_status == "testing" and
                    master_gen == self.generation_id and
                    master_chunk < master_chunks):
                    start_chunk = master_chunk  # resume from next chunk after the one we were on
                    logger.info(f"Crash recovery: resuming from chunk {start_chunk + 1}/{master_chunks} "
                                f"(was on chunk {master_chunk})")

        # 6. Run worker-side chunked testing
        await self._run_chunked_testing(
            test_urls, ping_thresh, http_timeout, concurrent, speed_top_n, schedule_interval, start_chunk
        )

        # 7. Update last test completion time
        self.last_test_completed_at = datetime.now(timezone.utc)

    async def _run_chunked_testing(
        self, test_urls, ping_thresh, http_timeout, concurrent,
        speed_top_n, schedule_interval, start_chunk: int = 0
    ):
        """Fetch ALL proxies once, slice into chunks locally, test & report each chunk.

        Args:
            start_chunk: 0 = start from beginning; N > 0 = resume from chunk N+1
                         (used for crash recovery after reading master state).
        """
        from tester import run_proxy_checks
        from speed_tester import _measure_speed, _compute_speed_score

        # Fetch all proxies at once
        run_id, all_urls, total, chunk_size = await self.get_all_proxies()
        if not all_urls:
            logger.info("No proxies available from master. Idling.")
            await self.report_status("idle", 0, 0, self.generation_id)
            return

        # If chunk_size is 0, treat the whole list as a single chunk
        if chunk_size <= 0:
            chunk_size = len(all_urls)

        # Build local chunk list
        chunks = [
            all_urls[i:i + chunk_size]
            for i in range(0, len(all_urls), chunk_size)
        ]
        total_chunks = len(chunks)
        logger.info(
            f"Worker-side chunking: {len(all_urls)} proxies, "
            f"chunk_size={chunk_size}, total_chunks={total_chunks}, "
            f"start_chunk={start_chunk}, run_id={run_id}"
        )

        total_checked = 0
        total_passed = 0

        # Report initial status: testing from start_chunk (0-indexed, +1 for display)
        await self.report_status("testing", start_chunk + 1, total_chunks, self.generation_id)

        for idx in range(start_chunk, total_chunks):
            raw_urls = chunks[idx]
            chunk_num = idx + 1  # 1-indexed for display

            logger.info(f"Testing chunk {chunk_num}/{total_chunks} "
                        f"({len(raw_urls)} proxies, offset={idx * chunk_size})...")

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

            total_checked += status_dict["checked"]
            total_passed += status_dict["passed"]
            logger.info(f"Chunk {chunk_num}: {status_dict['passed']} passed, {status_dict['failed']} failed")

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
                    r["ping_ms"], r["tests_passed"],
                    r["download_speed_kbps"], r["upload_speed_kbps"]
                )

            # Optional speed testing for top N proxies in chunk
            if speed_top_n > 0 and valid_proxies:
                to_test = sorted(valid_proxies, key=lambda p: (-p.tests_passed, p.ping_ms))[:speed_top_n]
                speed_sem = asyncio.Semaphore(2)
                counter_lock = asyncio.Lock()
                done = 0

                logger.info(f"Speed tests for top {len(to_test)} proxies in chunk...")

                async def _speed_one(p: object):
                    nonlocal done
                    async with speed_sem:
                        result = await _measure_speed(p.raw_url, timeout_s=max(http_timeout + 10, 20))
                        speed_score = 0.0
                        dl, ul = 0, 0
                        if result:
                            dl, ul = result
                            p.download_speed_kbps = dl
                            p.upload_speed_kbps = ul
                            speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, dl, ul)
                            p.speed_score = speed_score
                        else:
                            speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, 0, 0)
                            p.speed_score = speed_score
                        async with counter_lock:
                            done += 1
                            logger.info(f"⚡ Speed [{p.ping_ms}ms] DL={dl}KB/s UL={ul}KB/s "
                                        f"Score={speed_score:.0f} ({done}/{len(to_test)})")
                        for r in all_tested_results:
                            if r["raw_url"] == p.raw_url:
                                r["download_speed_kbps"] = dl
                                r["upload_speed_kbps"] = ul
                                r["speed_score"] = speed_score
                                break

                await asyncio.gather(*[_speed_one(p) for p in to_test])

            # Report results for this chunk
            reported = await self.report_results(
                all_tested_results, checked_count=status_dict["checked"], is_partial=True
            )
            if reported:
                logger.info(f"Reported chunk {chunk_num} results (is_partial=True)")
            else:
                logger.warning(f"Failed to report chunk {chunk_num} results, continuing anyway.")

            # Report progress after each chunk
            await self.report_status("testing", chunk_num, total_chunks, self.generation_id)

        # All chunks done — report idle
        await self.report_status("idle", total_chunks, total_chunks, self.generation_id)

        next_in = f" Next test in ~{schedule_interval}min." if schedule_interval > 0 else ""
        logger.info(f"Chunked testing complete. {total_checked} checked, {total_passed} passed.{next_in}")

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
            # Register only once (on first iteration) or after a failed registration.
            # Do NOT re-register on every wake-up — that was the root cause of the wl bug.
            if app.node_id is None:
                await app.register()
                if app.node_id is None:
                    # Registration failed — wait and retry
                    await asyncio.sleep(config.poll_interval_s)
                    continue

            if app._already_active:
                # Another instance is active — wait and check again
                logger.debug("Waiting because another instance is active...")
                await asyncio.sleep(config.poll_interval_s)
                # Reset flag AND node_id so we re-register and re-check status
                app._already_active = False
                app.node_id = None
                continue

            if app.node_id:
                await app.run_testing_cycle()

        except Exception as e:
            logger.error(f"Unhandled error in main loop: {repr(e)}")
            app.node_id = None  # Force re-register on next iteration

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
