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
        """Fetch proxies and run_id from master. Returns (run_id, proxy_list)."""
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

    async def report_results(self, results):
        if not self.node_id:
            return False
            
        try:
            resp = await self.http_client.post(f"{self.master_url}/api/node/results", json={
                "node_id": self.node_id,
                "results": results
            })
            if resp.status_code == 200:
                logger.info(f"Successfully reported {len(results)} results to master.")
                return True
            else:
                logger.error(f"Failed to report results: HTTP {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error reporting results: {e}")
            return False

    async def run_testing_cycle(self):
        # 1. Get configs from master
        test_config = await self.get_test_config()
        if not test_config:
            logger.warning("Could not fetch test config, skipping cycle.")
            return

        urls = []
        # Convert remote test URLs into local config class
        # from tester import TestUrl (We redefine or just use a dict for simplicity)
        from pydantic import BaseModel
        class MinimalTestUrl(BaseModel):
            url: str
            expect_status: int = 200
            min_body_bytes: int = 100

        for u in test_config.get("test_urls", []):
            urls.append(MinimalTestUrl(
                url=u["url"], 
                expect_status=u["expect_status"], 
                min_body_bytes=u["min_body_bytes"]
            ))
            
        ping_thresh = test_config.get("ping_threshold_ms", 1500)
        http_timeout = test_config.get("http_timeout_s", 10)
        concurrent = test_config.get("concurrent_checks_limit", config.concurrent_checks)
        speed_top_n = test_config.get("speed_test_top_n", 0)

        # 2. Get Proxies and check if list changed
        run_id, raw_urls = await self.get_proxies()
        if not raw_urls:
            logger.info("No proxies provided by master. Idling.")
            return

        if run_id == self.last_run_id:
            logger.info(f"Master list unchanged (run_id={run_id}). Skipping test cycle.")
            return

        logger.info(f"New proxy list detected! run_id={run_id} (prev={self.last_run_id}). Starting tests with {len(raw_urls)} proxies...")

        # 3. Test Proxies (We use singbox_runner directly to keep dependencies light, or tester module)
        # Because we're a node, we should run the test similar to _background_test:
        from proxy_parsers import parse_proxy_url
        from tester import run_proxy_checks
        from speed_tester import speed_test_proxies
        
        parsed = []
        for raw in raw_urls:
            p = parse_proxy_url(raw)
            if p:
                parsed.append(p)
                
        if not parsed:
            logger.warning("No valid proxy parsed.")
            return

        status_dict = {
            "running": True,
            "current_phase": "pinging",
            "checked": 0,
            "total": len(parsed),
            "passed": 0,
            "failed": 0,
        }
        
        # Test basic connectivity + URLs
        valid_proxies = await run_proxy_checks(
            parsed, urls, ping_thresh, http_timeout, concurrent, status_dict,
            singbox_path=config.singbox_path,
            port_start=config.singbox_port
        )
        
        # Format results
        final_results = []
        for p in valid_proxies:
            final_results.append({
                "raw_url": p.raw_url,
                "ping_ms": p.ping_ms,
                "tests_passed": p.tests_passed,
                "tests_total": p.tests_total,
                "download_speed_kbps": p.download_speed_kbps,
                "upload_speed_kbps": p.upload_speed_kbps,
                "speed_score": p.speed_score
            })
            
        # Optional Speed testing phase if master requested it
        if speed_top_n > 0 and final_results:
            logger.info(f"Running speed tests for top {speed_top_n} proxies...")
            # We must pass ProxyResult-like objects to speed_test_proxies. 
            # We will patch the attributes locally.
            class DummyProxyResult:
                def __init__(self, **kw):
                    self.__dict__.update(kw)
            
            objs = [DummyProxyResult(**r) for r in final_results]
            
            await speed_test_proxies(
                objs, 
                top_n=speed_top_n, 
                singbox_path=config.singbox_path,
                port_start=config.singbox_port + 1000 # Offset to avoid conflict
            )
            
            # Repack results
            final_results = []
            for o in objs:
                final_results.append({
                    "raw_url": o.raw_url,
                    "ping_ms": o.ping_ms,
                    "tests_passed": o.tests_passed,
                    "tests_total": o.tests_total,
                    "download_speed_kbps": o.download_speed_kbps,
                    "upload_speed_kbps": o.upload_speed_kbps,
                    "speed_score": o.speed_score
                })
        
        # 4. Report results and save run_id
        reported = await self.report_results(final_results)
        if reported:
            self.last_run_id = run_id
            logger.info(f"Saved run_id={run_id}. Will idle until master produces a new list.")


async def main():
    logger.info("Initializing VPN Checker Node...")
    app = NodeApp()
    
    while True:
        try:
            logger.info("Waking up for check-in...")
            if not app.node_id:
                await app.register()
            else:
                # Basic heartbeat to keep session alive and notify IP changes
                await app.register()
                
            if app.node_id:
                # Cycle
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
