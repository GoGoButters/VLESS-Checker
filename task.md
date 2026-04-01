# Multi-Protocol Migration Task List

**Frontend / UI Completion (Logs & Nodes)**
- [x] Create `logs.html` for real-time monitoring dashboard
      - Add auto-scroll and auto-update (AJAX polling) logic
      - Format raw log messages into colored badges (ERROR, INFO, etc)
- [x] Create `nodes.html` to visualize connected workers
      - Display node connection history, tested vs passed proxy metrics
      - Add easy copy-paste webhook deployment for each specific node
- [x] Update `dashboard.html` to integrate node metrics into stats cards
- [x] Update `settings.html` to configure:
      - `node_api_token` (bearer token generation)
      - `node_check_top_n` (amount of proxies sent to nodes)
      - `speed_test_top_n` limit

**Worker Node Implementation (Headless Client)**
- [x] Create new isolated environment/module `node/` (Python/FastAPI not required, simple requests loop)
- [x] Build `node_client.py` pulling logic:
      - Fetch `node_api_token` injected by Docker ENV
      - Query master API for test jobs `GET /api/node/proxies`
      - Reuse existing `singbox_runner.py` / `tester.py` pipeline (minus UI dependencies)
      - Submit HTTP Ping results via `POST /api/node/results`
- [x] Dockerize Node Client (`Dockerfile.node`) allowing quick remote VPS deployments

- [ ] Phase 4: Container Environment
  - [ ] Revamp `Dockerfile` to automatically fetch `sing-box` based on the system architecture.
  - [ ] Revamp `docker-compose.yml` ENV overrides.

- [ ] Phase 5: Testing & Debugging Loop
  - [ ] Complete docker build & start routine.
  - [ ] Execute `browser_subagent` to upload diverse links and run the full testing pipeline.
  - [ ] Examine container logs for parse faults or JSON configuration crash loops.

- [ ] Phase 6: Release Updates
  - [ ] Walkthrough updating.
  - [ ] Git push to the `VLESS-Checker` repository (should we rename it? "Vpn-Checker").
