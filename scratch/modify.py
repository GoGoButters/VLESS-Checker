import codecs

with codecs.open('main.py', 'r', 'utf-8') as f:
    text = f.read()

# 1. node_get_config
text = text.replace('"geo_check_enabled": settings.geo_check_enabled if settings else False,', '"geo_check_enabled": True,')

# 2. add_rating
text = text.replace(
'''async def add_rating(
    request: Request,
    name: str = Form(...),
    webhook_path: str = Form(...),
    max_proxies: int = Form(0),
    min_dl_kbps: int = Form(0),
    min_ul_kbps: int = Form(0),
    rename_prefix: str = Form(""),
    consensus_only: int = Form(0),
    geo_top_n: int = Form(1),
):''', 
'''async def add_rating(
    request: Request,
    name: str = Form(...),
    webhook_path: str = Form(...),
    max_proxies: int = Form(0),
    min_dl_kbps: int = Form(0),
    min_ul_kbps: int = Form(0),
    rename_prefix: str = Form(""),
    consensus_only: int = Form(0),
    geo_check_enabled: int = Form(0),
    geo_top_n: int = Form(1),
):''')

text = text.replace(
'''            min_ul_kbps=max(0, min_ul_kbps),
            rename_prefix=rename_prefix.strip(),
            consensus_only=bool(consensus_only),
            geo_top_n=max(1, geo_top_n),
        )''',
'''            min_ul_kbps=max(0, min_ul_kbps),
            rename_prefix=rename_prefix.strip(),
            consensus_only=bool(consensus_only),
            geo_check_enabled=bool(geo_check_enabled),
            geo_top_n=max(1, geo_top_n),
        )''')

# 3. edit_rating
text = text.replace(
'''async def edit_rating(
    request: Request,
    rating_id: int,
    name: str = Form(...),
    webhook_path: str = Form(...),
    max_proxies: int = Form(0),
    min_dl_kbps: int = Form(0),
    min_ul_kbps: int = Form(0),
    rename_prefix: str = Form(""),
    consensus_only: int = Form(0),
    geo_top_n: int = Form(1),
):''',
'''async def edit_rating(
    request: Request,
    rating_id: int,
    name: str = Form(...),
    webhook_path: str = Form(...),
    max_proxies: int = Form(0),
    min_dl_kbps: int = Form(0),
    min_ul_kbps: int = Form(0),
    rename_prefix: str = Form(""),
    consensus_only: int = Form(0),
    geo_check_enabled: int = Form(0),
    geo_top_n: int = Form(1),
):''')

text = text.replace(
'''            rg.rename_prefix = rename_prefix.strip()
            rg.consensus_only = bool(consensus_only)
            rg.geo_top_n = max(1, geo_top_n)
            session.add(rg)''',
'''            rg.rename_prefix = rename_prefix.strip()
            rg.consensus_only = bool(consensus_only)
            rg.geo_check_enabled = bool(geo_check_enabled)
            rg.geo_top_n = max(1, geo_top_n)
            session.add(rg)''')

with codecs.open('main.py', 'w', 'utf-8') as f:
    f.write(text)
print('Done modifying main.py')
