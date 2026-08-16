"""Geo checker — detects proxy country via GeoIP APIs through the proxy itself.

Uses multiple free GeoIP APIs with fallback, and maps country codes to Russian names.
Designed to be called from worker nodes after speed testing.
"""

import asyncio
import json
import logging
import os
import socket
import tempfile

import httpx

from proxy_parsers import parse_proxy_url

logger = logging.getLogger("vpn_checker.geo_checker")

SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")

# GeoIP API endpoints (free, no auth required)
# Each returns JSON with country info accessible via different keys
GEOIP_APIS = [
    {
        "url": "http://ip-api.com/json/?fields=countryCode",
        "key": "countryCode",
    },
    {
        "url": "https://ipapi.co/json/",
        "key": "country_code",
    },
    {
        "url": "https://ipinfo.io/json",
        "key": "country",
    },
]

# ISO 3166-1 alpha-2 country code → Russian country name
COUNTRY_NAMES_RU = {
    "AD": "Андорра",
    "AE": "ОАЭ",
    "AF": "Афганистан",
    "AG": "Антигуа и Барбуда",
    "AI": "Ангилья",
    "AL": "Албания",
    "AM": "Армения",
    "AO": "Ангола",
    "AR": "Аргентина",
    "AS": "Американское Самоа",
    "AT": "Австрия",
    "AU": "Австралия",
    "AW": "Аруба",
    "AZ": "Азербайджан",
    "BA": "Босния и Герцеговина",
    "BB": "Барбадос",
    "BD": "Бангладеш",
    "BE": "Бельгия",
    "BF": "Буркина-Фасо",
    "BG": "Болгария",
    "BH": "Бахрейн",
    "BI": "Бурунди",
    "BJ": "Бенин",
    "BM": "Бермуды",
    "BN": "Бруней",
    "BO": "Боливия",
    "BR": "Бразилия",
    "BS": "Багамы",
    "BT": "Бутан",
    "BW": "Ботсвана",
    "BY": "Беларусь",
    "BZ": "Белиз",
    "CA": "Канада",
    "CD": "ДР Конго",
    "CF": "ЦАР",
    "CG": "Конго",
    "CH": "Швейцария",
    "CI": "Кот-д'Ивуар",
    "CL": "Чили",
    "CM": "Камерун",
    "CN": "Китай",
    "CO": "Колумбия",
    "CR": "Коста-Рика",
    "CU": "Куба",
    "CV": "Кабо-Верде",
    "CW": "Кюрасао",
    "CY": "Кипр",
    "CZ": "Чехия",
    "DE": "Германия",
    "DJ": "Джибути",
    "DK": "Дания",
    "DM": "Доминика",
    "DO": "Доминикана",
    "DZ": "Алжир",
    "EC": "Эквадор",
    "EE": "Эстония",
    "EG": "Египет",
    "ER": "Эритрея",
    "ES": "Испания",
    "ET": "Эфиопия",
    "FI": "Финляндия",
    "FJ": "Фиджи",
    "FK": "Фолклендские о-ва",
    "FM": "Микронезия",
    "FO": "Фарерские о-ва",
    "FR": "Франция",
    "GA": "Габон",
    "GB": "Великобритания",
    "GD": "Гренада",
    "GE": "Грузия",
    "GF": "Гвиана",
    "GG": "Гернси",
    "GH": "Гана",
    "GI": "Гибралтар",
    "GL": "Гренландия",
    "GM": "Гамбия",
    "GN": "Гвинея",
    "GQ": "Экваториальная Гвинея",
    "GR": "Греция",
    "GT": "Гватемала",
    "GU": "Гуам",
    "GW": "Гвинея-Бисау",
    "GY": "Гайана",
    "HK": "Гонконг",
    "HN": "Гондурас",
    "HR": "Хорватия",
    "HT": "Гаити",
    "HU": "Венгрия",
    "ID": "Индонезия",
    "IE": "Ирландия",
    "IL": "Израиль",
    "IM": "Остров Мэн",
    "IN": "Индия",
    "IQ": "Ирак",
    "IR": "Иран",
    "IS": "Исландия",
    "IT": "Италия",
    "JE": "Джерси",
    "JM": "Ямайка",
    "JO": "Иордания",
    "JP": "Япония",
    "KE": "Кения",
    "KG": "Кыргызстан",
    "KH": "Камбоджа",
    "KI": "Кирибати",
    "KM": "Коморы",
    "KN": "Сент-Китс и Невис",
    "KP": "КНДР",
    "KR": "Южная Корея",
    "KW": "Кувейт",
    "KY": "Каймановы о-ва",
    "KZ": "Казахстан",
    "LA": "Лаос",
    "LB": "Ливан",
    "LC": "Сент-Люсия",
    "LI": "Лихтенштейн",
    "LK": "Шри-Ланка",
    "LR": "Либерия",
    "LS": "Лесото",
    "LT": "Литва",
    "LU": "Люксембург",
    "LV": "Латвия",
    "LY": "Ливия",
    "MA": "Марокко",
    "MC": "Монако",
    "MD": "Молдова",
    "ME": "Черногория",
    "MG": "Мадагаскар",
    "MH": "Маршалловы о-ва",
    "MK": "Северная Македония",
    "ML": "Мали",
    "MM": "Мьянма",
    "MN": "Монголия",
    "MO": "Макао",
    "MP": "Северные Марианские о-ва",
    "MR": "Мавритания",
    "MS": "Монтсеррат",
    "MT": "Мальта",
    "MU": "Маврикий",
    "MV": "Мальдивы",
    "MW": "Малави",
    "MX": "Мексика",
    "MY": "Малайзия",
    "MZ": "Мозамбик",
    "NA": "Намибия",
    "NC": "Новая Каледония",
    "NE": "Нигер",
    "NF": "Остров Норфолк",
    "NG": "Нигерия",
    "NI": "Никарагуа",
    "NL": "Нидерланды",
    "NO": "Норвегия",
    "NP": "Непал",
    "NR": "Науру",
    "NZ": "Новая Зеландия",
    "OM": "Оман",
    "PA": "Панама",
    "PE": "Перу",
    "PF": "Французская Полинезия",
    "PG": "Папуа — Новая Гвинея",
    "PH": "Филиппины",
    "PK": "Пакистан",
    "PL": "Польша",
    "PM": "Сен-Пьер и Микелон",
    "PR": "Пуэрто-Рико",
    "PS": "Палестина",
    "PT": "Португалия",
    "PW": "Палау",
    "PY": "Парагвай",
    "QA": "Катар",
    "RE": "Реюньон",
    "RO": "Румыния",
    "RS": "Сербия",
    "RU": "Россия",
    "RW": "Руанда",
    "SA": "Саудовская Аравия",
    "SB": "Соломоновы о-ва",
    "SC": "Сейшелы",
    "SD": "Судан",
    "SE": "Швеция",
    "SG": "Сингапур",
    "SH": "Остров Святой Елены",
    "SI": "Словения",
    "SK": "Словакия",
    "SL": "Сьерра-Леоне",
    "SM": "Сан-Марино",
    "SN": "Сенегал",
    "SO": "Сомали",
    "SR": "Суринам",
    "SS": "Южный Судан",
    "ST": "Сан-Томе и Принсипи",
    "SV": "Сальвадор",
    "SX": "Синт-Мартен",
    "SY": "Сирия",
    "SZ": "Эсватини",
    "TC": "Тёркс и Кайкос",
    "TD": "Чад",
    "TG": "Того",
    "TH": "Таиланд",
    "TJ": "Таджикистан",
    "TK": "Токелау",
    "TL": "Восточный Тимор",
    "TM": "Туркменистан",
    "TN": "Тунис",
    "TO": "Тонга",
    "TR": "Турция",
    "TT": "Тринидад и Тобаго",
    "TV": "Тувалу",
    "TW": "Тайвань",
    "TZ": "Танзания",
    "UA": "Украина",
    "UG": "Уганда",
    "US": "США",
    "UY": "Уругвай",
    "UZ": "Узбекистан",
    "VA": "Ватикан",
    "VC": "Сент-Винсент и Гренадины",
    "VE": "Венесуэла",
    "VG": "Виргинские о-ва (Брит.)",
    "VI": "Виргинские о-ва (США)",
    "VN": "Вьетнам",
    "VU": "Вануату",
    "WS": "Самоа",
    "XK": "Косово",
    "YE": "Йемен",
    "ZA": "ЮАР",
    "ZM": "Замбия",
    "ZW": "Зимбабве",
}


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_singbox_config(outbound: dict, socks_port: int) -> dict:
    bind_interface = os.environ.get("BIND_INTERFACE", "")
    if bind_interface:
        outbound["bind_interface"] = bind_interface
    return {
        "log": {"disabled": True, "level": "error"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port
            }
        ],
        "outbounds": [
            outbound
        ]
    }


def get_country_name_ru(country_code: str) -> str:
    """Convert ISO 3166-1 alpha-2 country code to Russian name.
    Returns the code itself if no mapping found."""
    if not country_code:
        return ""
    code = country_code.upper().strip()
    return COUNTRY_NAMES_RU.get(code, code)


async def detect_proxy_country(
    proxy_url: str,
    timeout_s: int = 10,
    singbox_path: str = SINGBOX_PATH,
) -> str:
    """Detect the country of a proxy by making a GeoIP API call through it.
    
    Returns the country name in Russian (e.g. "США", "Германия"),
    or empty string if detection fails.
    """
    parsed_outbound = parse_proxy_url(proxy_url)
    if not parsed_outbound:
        return ""

    socks_port = _get_free_port()
    config = _build_singbox_config(parsed_outbound, socks_port)

    config_fd, config_path = tempfile.mkstemp(suffix=".json", prefix="geo_")
    try:
        with os.fdopen(config_fd, "w") as f:
            json.dump(config, f)

        proc = await asyncio.create_subprocess_exec(
            singbox_path, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            # Wait for sing-box to start
            await asyncio.sleep(1.5)

            if proc.returncode is not None:
                return ""

            local_proxy = f"socks5://127.0.0.1:{socks_port}"

            try:
                async with httpx.AsyncClient(
                    proxy=local_proxy,
                    timeout=httpx.Timeout(float(timeout_s)),
                    verify=False,
                    follow_redirects=True,
                ) as client:
                    # Try each GeoIP API until one works
                    for api in GEOIP_APIS:
                        try:
                            resp = await client.get(api["url"])
                            if resp.status_code == 200:
                                data = resp.json()
                                country_code = data.get(api["key"], "")
                                if country_code and len(country_code) == 2:
                                    country_ru = get_country_name_ru(country_code)
                                    logger.debug(
                                        f"Geo detected: {country_code} → {country_ru} "
                                        f"(via {api['url']})"
                                    )
                                    return country_ru
                        except Exception as e:
                            logger.debug(f"GeoIP API {api['url']} failed: {e}")
                            continue
            except Exception as e:
                logger.debug(f"GeoIP proxy connection failed: {e}")
                return ""

        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    finally:
        try:
            os.unlink(config_path)
        except Exception:
            pass
