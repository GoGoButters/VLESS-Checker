# Multi-Protocol Migration Task List

- [/] Phase 1: Core Parsing Engine
  - [ ] Implement `proxy_parsers.py` capable of translating `vless://`, `vmess://`, `trojan://`, `hy2://`, `ss://` to sing-box JSON dicts.
  - [ ] Write logic to decode standard Base64 links and VMess JSON data safely within pure Python.

- [ ] Phase 2: Engine Integration
  - [ ] Update `subs_manager.py` to identify and retain multi-protocol links (instead of strictly checking for `vless://`).
  - [ ] Update `tester.py` to correctly interface with `sing-box`: formatting the `config.json` properly, launching it (with `sing-box run -c`), mapping paths correctly.

- [ ] Phase 3: Data Integrity
  - [ ] Refactor `database.py`: create a new schema alias (e.g., `ProxyResult` instead of `ValidProxy`) to force SQLite initialization without migration clashes.
  - [ ] Update webhook generator in `main.py` to dish out generic `proxy_url` string instead of `vless_url`.

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
