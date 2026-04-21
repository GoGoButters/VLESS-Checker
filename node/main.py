import asyncio
import logging
import os
import sys
import httpx

# Add parent dir to path to import proxy_parsers and tester logic
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger("vpn_checker_node")

class NodeApp:
    def __init__(self):
        self.master_url = config.master_url.rstrip("/")
        self.node_id = None
        self.last_run_id = None  # Track the master's proxy list version
        self.http_client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {config.node_token}"},
            timeout=30.0
        )

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

        # 2. Get raw proxies from master and check if list changed
        run_id, raw_urls = await self.get_proxies()
        if not raw_urls:
            logger.info("No proxies available from master. Idling.")
            return

        if run_id == self.last_run_id:
            logger.info(f"Master proxy list unchanged (run_id={run_id}). Skipping test cycle.")
            return

        logger.info(f"New proxy list detected! run_id={run_id} (prev={self.last_run_id}). Starting tests with {len(raw_urls)} proxies...")

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

        # 4. Optional: Speed testing phase
        if speed_top_n > 0 and valid_proxies:
            from speed_tester import _measure_speed, _compute_speed_score
            logger.info(f"Running speed tests for top {min(speed_top_n, len(valid_proxies))} proxies...")

            to_test = sorted(valid_proxies, key=lambda p: (-p.tests_passed, p.ping_ms))[:speed_top_n]
            for p in to_test:
                result = await _measure_speed(p.raw_url, timeout_s=http_timeout + 5)
                if result:
                    dl, ul = result
                    p.download_speed_kbps = dl
                    p.upload_speed_kbps = ul
                    p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, dl, ul)
                    logger.info(f"⚡ Speed [{p.ping_ms}ms] DL={dl}KB/s UL={ul}KB/s Score={p.speed_score:.0f}")
                else:
                    p.speed_score = _compute_speed_score(p.ping_ms, p.tests_passed, 0, 0)

        # 5. Format results for reporting
        final_results = []
        for p in valid_proxies:
            final_results.append({
                "raw_url": p.raw_url,
                "ping_ms": p.ping_ms,
                "tests_passed": p.tests_passed,
                "tests_total": p.tests_total,
                "download_speed_kbps": getattr(p, "download_speed_kbps", 0),
                "upload_speed_kbps": getattr(p, "upload_speed_kbps", 0),
                "speed_score": getattr(p, "speed_score", 0.0),
            })

        # 6. Report results and save run_id
        reported = await self.report_results(final_results, checked_count=status_dict["checked"])
        if reported:
            self.last_run_id = run_id
            logger.info(f"Saved run_id={run_id}. Will idle until master produces a new proxy list.")



async def main():
    logger.info("Initializing VPN Checker Worker Node...")
    app = NodeApp()
    
    while True:
        try:
            logger.info("Waking up for check-in...")
            # Always register/re-register to keep heartbeat alive
            await app.register()
                
            if app.node_id:
                await app.run_testing_cycle()
                
        except Exception as e:
            logger.error(f"Unhandled error in main loop: {e}")
            
        logger.info(f"Sleeping for {config.poll_interval_s} seconds...")
        await asyncio.sleep(config.poll_interval_s)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Node shut down by user.")
