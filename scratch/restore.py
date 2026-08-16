import sys
import codecs

with codecs.open('scratch/main_old.py', 'r', 'utf-8') as f:
    old_lines = f.readlines()

func1_start = 1757 - 1
func1_end = 1799

func2_start = 1801 - 1
func2_end = 1948

# We rewrite func2
new_func2 = """
@app.get("/{secret_path:path}")
async def webhook_output(secret_path: str):
    with Session(engine) as session:
        # Check if secret_path matches a RatingGroup
        group = session.exec(select(RatingGroup).where(RatingGroup.webhook_path == secret_path)).first()
        if not group:
            raise HTTPException(status_code=404)
        
        # Cleanup stale node data (marks offline nodes, deletes orphan results)
        cleanup_stats = _cleanup_stale_node_data(session)
        
        # RE-LOAD group after cleanup
        group = session.get(RatingGroup, group.id)
        if not group:
            raise HTTPException(status_code=404)
        
        online_ids = cleanup_stats.get("online_ids", [])
        if not online_ids:
            logger.warning("Webhook: no online nodes, returning empty list")
            return PlainTextResponse("", media_type="text/plain; charset=utf-8")
        
        online_ids_set = set(online_ids)

        # Get linked nodes for this group
        links = session.exec(select(NodeRatingLink).where(NodeRatingLink.rating_group_id == group.id)).all()
        linked_node_ids = {link.node_id for link in links}
        # Intersect with online_ids
        target_node_ids = online_ids_set & linked_node_ids

        if not target_node_ids:
            logger.warning(f"Webhook {secret_path}: no target online nodes, returning empty list")
            return PlainTextResponse("", media_type="text/plain; charset=utf-8")
        
        # Load results only from target nodes where tests_passed > 0
        all_results = session.exec(
            select(NodeProxyResult)
            .where(NodeProxyResult.tests_passed > 0)
            .where(NodeProxyResult.node_id.in_(target_node_ids))
        ).all()
        
        # Aggregate: best result per (identity, node_id), then compute averages
        avg_data = _compute_webhook_averages(all_results)
        
        # Determine filtering parameters
        consensus_only = group.consensus_only
        min_dl = group.min_dl_kbps or 0
        min_ul = group.min_ul_kbps or 0
        geo_top_n = max(1, group.geo_top_n or 1)
        top_n = group.max_proxies or 0
        prefix = (group.rename_prefix or "").strip()
        geo_enabled = group.geo_check_enabled

        # Consensus-only filter
        if consensus_only:
            consensus_threshold = len(target_node_ids)
            if consensus_threshold > 0:
                consensus_data = {}
                for pid, d in avg_data.items():
                    if len(d["node_ids"]) >= consensus_threshold:
                        consensus_data[pid] = d
                avg_data = consensus_data
        
        # Apply speed filters BEFORE sorting and limiting
        filtered_data = {}
        for pid, d in avg_data.items():
            if (min_dl == 0 or d["avg_dl"] >= min_dl) and (min_ul == 0 or d["avg_ul"] >= min_ul):
                filtered_data[pid] = d
        
        # Geo-check deduplication
        if geo_enabled:
            country_proxies: dict[str, list[tuple[str, dict]]] = {}
            for pid, d in filtered_data.items():
                country = d.get("country_name", "").strip()
                if not country or country.lower() == "unknown":
                    continue
                if country.lower() == "украина":
                    continue
                if country not in country_proxies:
                    country_proxies[country] = []
                country_proxies[country].append((pid, d))
            
            deduped_data = {}
            for country, proxies in country_proxies.items():
                proxies.sort(key=lambda x: x[1]["avg_score"], reverse=True)
                for pid, d in proxies[:geo_top_n]:
                    deduped_data[pid] = d
            
            filtered_data = deduped_data
        
        # Sort: node_count (desc) → avg_score (desc)
        sorted_pids = sorted(
            filtered_data.keys(),
            key=lambda pid: (len(filtered_data[pid]["node_ids"]), filtered_data[pid]["avg_score"]),
            reverse=True,
        )
        
        # Limit to top-N
        if top_n > 0:
            sorted_pids = sorted_pids[:top_n]
        
        # Build output lines with appropriate naming
        lines = []
        if geo_enabled:
            country_counters: dict[str, int] = {}
            for pid in sorted_pids:
                url = filtered_data[pid]["raw_url"]
                country = filtered_data[pid].get("country_name", "").strip()
                if country:
                    country_counters[country] = country_counters.get(country, 0) + 1
                    idx = country_counters[country]
                    if geo_top_n > 1:
                        remark = f"{country} {idx}"
                    else:
                        remark = country
                    url = replace_proxy_remark(url, remark)
                else:
                    continue
                lines.append(url)
        else:
            for i, pid in enumerate(sorted_pids, start=1):
                url = filtered_data[pid]["raw_url"]
                if prefix:
                    url = replace_proxy_remark(url, f"{prefix} - {i}")
                lines.append(url)
        
        return PlainTextResponse("\\n".join(lines), media_type="text/plain; charset=utf-8")
"""

with codecs.open('main.py', 'r', 'utf-8') as f:
    main_lines = f.readlines()

insert_idx = -1
for i, line in enumerate(main_lines):
    if '# ---------------------------------------------------------------------------' in line and 'Run with uvicorn' in main_lines[i+1]:
        insert_idx = i
        break

if insert_idx != -1:
    to_insert = "".join(old_lines[func1_start:func1_end]) + "\n" + new_func2 + "\n\n"
    main_lines.insert(insert_idx, to_insert)
    with codecs.open('main.py', 'w', 'utf-8') as f:
        f.writelines(main_lines)
    print("Successfully restored webhook_output!")
else:
    print("Could not find insertion point!")
