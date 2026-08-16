import codecs

with codecs.open('templates/ratings.html', 'r', 'utf-8') as f:
    text = f.read()

# Add to Add Modal
add_modal_search = '''<label class="flex items-center gap-3 cursor-pointer pt-2">
                    <input type="checkbox" name="consensus_only" value="1"
                        class="w-5 h-5 rounded bg-slate-800 border border-slate-600 text-indigo-500 focus:ring-indigo-500">
                    <span class="text-sm text-slate-200">Consensus-only mode (require all linked online nodes)</span>
                </label>'''

add_modal_replace = '''<label class="flex items-center gap-3 cursor-pointer pt-2">
                    <input type="checkbox" name="consensus_only" value="1"
                        class="w-5 h-5 rounded bg-slate-800 border border-slate-600 text-indigo-500 focus:ring-indigo-500">
                    <span class="text-sm text-slate-200">Consensus-only mode (require all linked online nodes)</span>
                </label>
                <label class="flex items-center gap-3 cursor-pointer pt-2">
                    <input type="checkbox" name="geo_check_enabled" value="1"
                        class="w-5 h-5 rounded bg-slate-800 border border-slate-600 text-indigo-500 focus:ring-indigo-500">
                    <span class="text-sm text-slate-200">Country detection (GeoIP) - Distribute best proxy per country</span>
                </label>'''
text = text.replace(add_modal_search, add_modal_replace)

# Add to Edit Modal
edit_modal_search = '''<label class="flex items-center gap-3 cursor-pointer pt-2">
                    <input type="checkbox" name="consensus_only" id="edit_consensus_only" value="1"
                        class="w-5 h-5 rounded bg-slate-800 border border-slate-600 text-indigo-500 focus:ring-indigo-500">
                    <span class="text-sm text-slate-200">Consensus-only mode (require all linked online nodes)</span>
                </label>'''

edit_modal_replace = '''<label class="flex items-center gap-3 cursor-pointer pt-2">
                    <input type="checkbox" name="consensus_only" id="edit_consensus_only" value="1"
                        class="w-5 h-5 rounded bg-slate-800 border border-slate-600 text-indigo-500 focus:ring-indigo-500">
                    <span class="text-sm text-slate-200">Consensus-only mode (require all linked online nodes)</span>
                </label>
                <label class="flex items-center gap-3 cursor-pointer pt-2">
                    <input type="checkbox" name="geo_check_enabled" id="edit_geo_check_enabled" value="1"
                        class="w-5 h-5 rounded bg-slate-800 border border-slate-600 text-indigo-500 focus:ring-indigo-500">
                    <span class="text-sm text-slate-200">Country detection (GeoIP) - Distribute best proxy per country</span>
                </label>'''
text = text.replace(edit_modal_search, edit_modal_replace)

# Update editRating signature and invocation
invocation_search = "onclick=\"editRating({{ rating.id }}, '{{ rating.name|escape }}', '{{ rating.webhook_path|escape }}', {{ rating.max_proxies }}, {{ rating.min_dl_kbps }}, {{ rating.min_ul_kbps }}, '{{ rating.rename_prefix|escape }}', {{ 'true' if rating.consensus_only else 'false' }}, {{ rating.geo_top_n }})\""
invocation_replace = "onclick=\"editRating({{ rating.id }}, '{{ rating.name|escape }}', '{{ rating.webhook_path|escape }}', {{ rating.max_proxies }}, {{ rating.min_dl_kbps }}, {{ rating.min_ul_kbps }}, '{{ rating.rename_prefix|escape }}', {{ 'true' if rating.consensus_only else 'false' }}, {{ 'true' if rating.geo_check_enabled else 'false' }}, {{ rating.geo_top_n }})\""
text = text.replace(invocation_search, invocation_replace)

sig_search = "function editRating(id, name, path, maxP, minDL, minUL, prefix, consensus, geoTopN) {"
sig_replace = "function editRating(id, name, path, maxP, minDL, minUL, prefix, consensus, geoCheck, geoTopN) {"
text = text.replace(sig_search, sig_replace)

logic_search = "document.getElementById('edit_consensus_only').checked = consensus;"
logic_replace = "document.getElementById('edit_consensus_only').checked = consensus;\n    document.getElementById('edit_geo_check_enabled').checked = geoCheck;"
text = text.replace(logic_search, logic_replace)

with codecs.open('templates/ratings.html', 'w', 'utf-8') as f:
    f.write(text)
print("Done modifying ratings.html")
