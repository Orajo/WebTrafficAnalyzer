#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Traffic Analyzer & DDoS / Bot Detector
Kompleksowe narzędzie do analizy logów Apache, wykrywania ataków DDoS, botów i generowania interaktywnych raportów HTML z mapami Leaflet.
"""

import sys
import os
import re
import math
import json
import gzip
import fnmatch
import hashlib
import pathlib
import socket
import argparse
import glob
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime
import numpy as np

try:
    from geoip2.database import Reader
    from geoip2.errors import AddressNotFoundError
except ImportError:
    Reader = None
    AddressNotFoundError = Exception

if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ==============================================================================
# KONFIGURACJA I SŁOWNIKI
# ==============================================================================

# Biała lista adresów IP i podsieci (CIDR) wykluczonych z analizy
# (np. własne datacenter, serwery aplikacyjne, dedykowane systemy monitoringu)
DEFAULT_WHITELIST_IPS = [
    '217.153.27.58',  # Nasze datacenter
]

STATIC_EXTENSIONS = (
    '.css', '.js', '.mjs', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
    '.ico', '.bmp', '.tiff', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.map', '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.swf'
)

# Znane wyszukiwarki (autoryzowane boty)
SEARCH_ENGINE_BOTS = {
    'googlebot': 'Googlebot (Google Search)',
    'bingbot': 'Bingbot (Microsoft Bing)',
    'yandexbot': 'YandexBot (Yandex Search)',
    'baiduspider': 'Baiduspider (Baidu Search)',
    'duckduckbot': 'DuckDuckBot (DuckDuckGo)',
    'slurp': 'Yahoo! Slurp',
    'sogou': 'Sogou Spider',
    'exabot': 'Exabot',
    'facebookexternalhit': 'Facebook Crawler',
    'facebot': 'Facebot',
    'ia_archiver': 'Alexa / Internet Archive',
    'twitterbot': 'TwitterBot',
    'linkedinbot': 'LinkedInBot',
    'applebot': 'Applebot',
    'petalbot': 'PetalBot (Huawei Search)',
    'qwantify': 'Qwantify (Qwant)',
    'seznam': 'SeznamBot',
    'coccoc': 'CocCoc Bot',
    'mail.ru_bot': 'Mail.Ru Bot'
}

# Boty SEO, komercyjne, AI Scrapery
SEO_AND_AI_BOTS = {
    'ahrefsbot': 'AhrefsBot (SEO Crawler)',
    'semrushbot': 'SemrushBot (SEO Crawler)',
    'mj12bot': 'MJ12bot (Majestic SEO)',
    'dotbot': 'DotBot (Moz SEO)',
    'serpstatbot': 'SerpstatBot (SEO Crawler)',
    'bytespider': 'ByteSpider (ByteDance / TikTok Scraper)',
    'gptbot': 'GPTBot (OpenAI Web Scraper)',
    'chatgpt-user': 'ChatGPT-User (OpenAI)',
    'claudebot': 'ClaudeBot (Anthropic Scraper)',
    'anthropic-ai': 'Anthropic AI Crawler',
    'cohere-ai': 'Cohere AI Scraper',
    'ccbot': 'CCBot (Common Crawl)',
    'diffbot': 'Diffbot',
    'blexbot': 'BLEXBot',
    'turnitinbot': 'TurnitinBot',
    'zoominfobot': 'ZoominfoBot',
    'amazonbot': 'Amazonbot',
    'applebot-extended': 'Applebot-Extended (Apple AI Training)',
    'seekport': 'Seekport Crawler',
    'reflectionbot': 'ReflectionBot (AI / Scraper)'
}

# Narzędzia skanujące, headless browsery, biblioteki skryptowe
SUSPICIOUS_TOOLS = {
    'headlesschrome': 'Headless Chrome (Automatyzacja/Scraper)',
    'puppeteer': 'Puppeteer (Headless Browser)',
    'playwright': 'Playwright (Headless Browser)',
    'selenium': 'Selenium (Web Automation)',
    'python-requests': 'Python Requests (Skrypt)',
    'aiohttp': 'Python aiohttp (Skrypt)',
    'httpx': 'Python HTTPX (Skrypt)',
    'urllib': 'Python urllib (Skrypt)',
    'curl': 'cURL (CLI Tool)',
    'wget': 'Wget (CLI Tool)',
    'go-http-client': 'Go HTTP Client (Skrypt)',
    'java/': 'Java HTTP Client',
    'apache-httpclient': 'Apache HttpClient',
    'libwww-perl': 'Perl LWP',
    'scrapy': 'Scrapy (Web Scraper)',
    'sqlmap': 'SQLMap (Penetration Tool)',
    'nikto': 'Nikto (Vulnerability Scanner)',
    'nmap': 'Nmap Scripting Engine',
    'masscan': 'Masscan Scanner',
    'zgrab': 'ZGrab Scanner',
    'censys': 'Censys Scanner',
    'shodan': 'Shodan Scanner',
    'nuclei': 'Nuclei Vulnerability Scanner',
    'zabbix': 'Zabbix (Monitoring)',
    'prometheus': 'Prometheus (Monitoring)'
}

# Współrzędne stolic/centrów krajów do mapy Leaflet
COUNTRY_COORDS = {
    'Poland': [52.2297, 21.0122], 'Polska': [52.2297, 21.0122], 'PL': [52.2297, 21.0122],
    'United States': [37.0902, -95.7129], 'Stany Zjednoczone': [37.0902, -95.7129], 'US': [37.0902, -95.7129],
    'Germany': [51.1657, 10.4515], 'Niemcy': [51.1657, 10.4515], 'DE': [51.1657, 10.4515],
    'France': [46.2276, 2.2137], 'Francja': [46.2276, 2.2137], 'FR': [46.2276, 2.2137],
    'United Kingdom': [55.3781, -3.4360], 'Wielka Brytania': [55.3781, -3.4360], 'GB': [55.3781, -3.4360],
    'Netherlands': [52.1326, 5.2913], 'Holandia': [52.1326, 5.2913], 'NL': [52.1326, 5.2913],
    'China': [35.8617, 104.1954], 'Chiny': [35.8617, 104.1954], 'CN': [35.8617, 104.1954],
    'Russia': [61.5240, 105.3188], 'Rosja': [61.5240, 105.3188], 'RU': [61.5240, 105.3188],
    'Ukraine': [48.3794, 31.1656], 'Ukraina': [48.3794, 31.1656], 'UA': [48.3794, 31.1656],
    'Czech Republic': [49.8175, 15.4730], 'Czechy': [49.8175, 15.4730], 'CZ': [49.8175, 15.4730],
    'Lithuania': [55.1694, 23.8813], 'Litwa': [55.1694, 23.8813], 'LT': [55.1694, 23.8813],
    'Sweden': [60.1282, 18.6435], 'Szwecja': [60.1282, 18.6435], 'SE': [60.1282, 18.6435],
    'Finland': [61.9241, 25.7482], 'Finlandia': [61.9241, 25.7482], 'FI': [61.9241, 25.7482],
    'Italy': [41.8719, 12.5674], 'Włochy': [41.8719, 12.5674], 'IT': [41.8719, 12.5674],
    'Spain': [40.4637, -3.7492], 'Hiszpania': [40.4637, -3.7492], 'ES': [40.4637, -3.7492],
    'Canada': [56.1304, -106.3468], 'Kanada': [56.1304, -106.3468], 'CA': [56.1304, -106.3468],
    'Brazil': [-14.2350, -51.9253], 'Brazylia': [-14.2350, -51.9253], 'BR': [-14.2350, -51.9253],
    'India': [20.5937, 78.9629], 'Indie': [20.5937, 78.9629], 'IN': [20.5937, 78.9629],
    'Japan': [36.2048, 138.2529], 'Japonia': [36.2048, 138.2529], 'JP': [36.2048, 138.2529],
    'Australia': [-25.2744, 133.7751], 'Australia': [-25.2744, 133.7751], 'AU': [-25.2744, 133.7751],
    'Singapore': [1.3521, 103.8198], 'Singapur': [1.3521, 103.8198], 'SG': [1.3521, 103.8198],
    'Hong Kong': [22.3193, 114.1694], 'Hongkong': [22.3193, 114.1694], 'HK': [22.3193, 114.1694],
    'Ireland': [53.1424, -7.6921], 'Irlandia': [53.1424, -7.6921], 'IE': [53.1424, -7.6921],
    'Switzerland': [46.8182, 8.2275], 'Szwajcaria': [46.8182, 8.2275], 'CH': [46.8182, 8.2275],
    'Austria': [47.5162, 14.5501], 'Austria': [47.5162, 14.5501], 'AT': [47.5162, 14.5501],
    'Norway': [60.4720, 8.4689], 'Norwegia': [60.4720, 8.4689], 'NO': [60.4720, 8.4689],
    'Romania': [45.9432, 24.9668], 'Rumunia': [45.9432, 24.9668], 'RO': [45.9432, 24.9668],
    'Bulgaria': [42.7339, 25.4858], 'Bułgaria': [42.7339, 25.4858], 'BG': [42.7339, 25.4858],
    'Seychelles': [-4.6796, 55.4920], 'Seszele': [-4.6796, 55.4920], 'SC': [-4.6796, 55.4920],
    'Panama': [8.5379, -80.7821], 'Panama': [8.5379, -80.7821], 'PA': [8.5379, -80.7821],
    'Cyprus': [35.1264, 33.4299], 'Cypr': [35.1264, 33.4299], 'CY': [35.1264, 33.4299],
    'Vietnam': [14.0583, 108.2772], 'Wietnam': [14.0583, 108.2772], 'VN': [14.0583, 108.2772],
    'Indonesia': [-0.7893, 113.9213], 'Indonezja': [-0.7893, 113.9213], 'ID': [-0.7893, 113.9213],
    'Moldova': [47.4116, 28.3699], 'Mołdawia': [47.4116, 28.3699], 'MD': [47.4116, 28.3699],
    'Unknown': [20.0, 0.0], 'Nieznany': [20.0, 0.0]
}

# Polskie lokalizacje i węzły sieciowe
POLISH_CITIES_COORDS = {
    'Warszawa': [52.2297, 21.0122],
    'Kraków': [50.0647, 19.9450],
    'Wrocław': [51.1079, 17.0385],
    'Poznań': [52.4064, 16.9252],
    'Gdańsk': [54.3520, 18.6466],
    'Katowice': [50.2649, 19.0238],
    'Łódź': [51.7592, 19.4560],
    'Szczecin': [53.4285, 14.5528],
    'Lublin': [51.2465, 22.5684],
    'Białystok': [53.1325, 23.1688],
    'Bydgoszcz': [53.1235, 18.0084],
    'Rzeszów': [50.0412, 21.9991],
    'Radom': [51.4027, 21.1471],
    'Płock': [52.5463, 19.7065],
    'Siedlce': [52.1678, 22.2901],
    'Olsztyn': [53.7784, 20.4801],
    'Toruń': [53.0138, 18.5984],
    'Częstochowa': [50.8118, 19.1203],
    'Gliwice': [50.2945, 18.6714],
    'Kielce': [50.8661, 20.6286]
}

ISP_CITY_MAP = {
    'orange': 'Warszawa',
    'polkomtel': 'Warszawa',
    'plus': 'Warszawa',
    't-mobile': 'Warszawa',
    'p4': 'Warszawa',
    'play': 'Warszawa',
    'upc': 'Warszawa',
    'vectra': 'Gdynia',
    'netia': 'Warszawa',
    'inea': 'Poznań',
    'toya': 'Łódź',
    'multimedia': 'Gdynia',
    'nask': 'Warszawa',
    'pionier': 'Poznań',
    'cyfronet': 'Kraków',
    'task': 'Gdańsk',
    'wcss': 'Wrocław',
    'atman': 'Warszawa',
    'exatel': 'Warszawa',
    '3s': 'Katowice',
    'korbank': 'Wrocław',
    'petrotel': 'Płock'
}

def clean_string(s):
    if not isinstance(s, str):
        return str(s) if s is not None else ""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s).strip()

def is_static_resource(url_path: str) -> bool:
    """Sprawdza czy URL prowadzi do zasobu statycznego (grafika, CSS, JS, fonty)."""
    path_clean = url_path.split('?')[0].lower()
    return path_clean.endswith(STATIC_EXTENSIONS)

def extract_section(url_path: str) -> str:
    """Wyciąga logiczną sekcję serwisu z URL."""
    clean_p = url_path.split('?')[0].strip('/')
    segments = [s for s in clean_p.split('/') if s]
    if not segments:
        return '/'
    if segments[0] in ('pl', 'en', 'de', 'ua', 'ru') and len(segments) >= 2:
        return f"/{segments[0]}/{segments[1]}"
    return f"/{segments[0]}"

def find_geoip_db(filename, user_path=None):
    """Wyszukuje pliki baz GeoLite2 w podanej ścieżce, katalogu skryptu, bieżącym katalogu lub systemowych lokalizacjach Linux."""
    if user_path and os.path.exists(user_path):
        return user_path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        user_path,
        filename,
        os.path.join(script_dir, filename) if script_dir else None,
        os.path.join(os.getcwd(), filename),
        os.path.join('/usr/share/GeoIP', filename),
        os.path.join('/var/lib/GeoIP', filename),
        os.path.join('/etc/httpd', filename),
        os.path.join('/etc/nginx', filename)
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return filename

class GeoResolver:
    """Obsługa zapytań GeoLite2 Country i ASN z automatyczną detekcją ścieżek baz danych."""
    def __init__(self, country_db_path='GeoLite2-Country.mmdb', asn_db_path='GeoLite2-ASN.mmdb'):
        self.country_reader = None
        self.asn_reader = None
        
        country_resolved = find_geoip_db('GeoLite2-Country.mmdb', country_db_path)
        asn_resolved = find_geoip_db('GeoLite2-ASN.mmdb', asn_db_path)
        
        if Reader:
            if country_resolved and os.path.exists(country_resolved):
                try:
                    self.country_reader = Reader(country_resolved)
                except Exception as e:
                    print(f"Ostrzeżenie: Nie udało się otworzyć bazy Country ({country_resolved}): {e}")
            if asn_resolved and os.path.exists(asn_resolved):
                try:
                    self.asn_reader = Reader(asn_resolved)
                except Exception as e:
                    print(f"Ostrzeżenie: Nie udało się otworzyć bazy ASN ({asn_resolved}): {e}")

    def get_country(self, ip: str) -> dict:
        if not self.country_reader:
            return {'code': 'XX', 'name_pl': 'Nieznany', 'name_en': 'Unknown'}
        try:
            resp = self.country_reader.country(ip)
            names = resp.country.names or {}
            iso = resp.country.iso_code or 'XX'
            name_pl = names.get('pl', names.get('en', resp.country.name or 'Nieznany'))
            name_en = names.get('en', resp.country.name or 'Unknown')
            return {'code': iso, 'name_pl': name_pl, 'name_en': name_en}
        except (AddressNotFoundError, ValueError):
            return {'code': 'XX', 'name_pl': 'Nieznany', 'name_en': 'Unknown'}
        except Exception:
            return {'code': 'XX', 'name_pl': 'Błąd', 'name_en': 'Error'}

    def get_asn(self, ip: str) -> dict:
        if not self.asn_reader:
            return {'asn': 0, 'org': 'Nieznany'}
        try:
            resp = self.asn_reader.asn(ip)
            return {
                'asn': resp.autonomous_system_number or 0,
                'org': resp.autonomous_system_organization or 'Nieznany'
            }
        except (AddressNotFoundError, ValueError):
            return {'asn': 0, 'org': 'Nieznany'}
        except Exception:
            return {'asn': 0, 'org': 'Błąd'}

def classify_user_agent(ua: str) -> dict:
    """Klasyfikuje User-Agent na: SEARCH_BOT, SEO_AI_BOT, SUSPICIOUS_TOOL, HUMAN_BROWSER, SUSPICIOUS_EMPTY."""
    if not ua or ua == '-' or ua == '""' or ua.strip() == '':
        return {
            'category': 'SUSPICIOUS_EMPTY',
            'label': 'Brak User-Agent (Pusty / Narzędzie)',
            'is_bot': True,
            'is_crawler': False,
            'is_malicious': True,
            'bot_name': 'Empty User-Agent',
            'threat_weight': 80
        }
    
    ua_l = ua.lower()
    
    # 1. Sprawdź znane roboty wyszukiwarek
    for key, name in SEARCH_ENGINE_BOTS.items():
        if key in ua_l:
            return {
                'category': 'SEARCH_BOT',
                'label': name,
                'is_bot': True,
                'is_crawler': True,
                'is_malicious': False,
                'bot_name': key,
                'threat_weight': 0
            }
            
    # 2. Sprawdź roboty SEO / AI
    for key, name in SEO_AND_AI_BOTS.items():
        if key in ua_l:
            return {
                'category': 'SEO_AI_BOT',
                'label': name,
                'is_bot': True,
                'is_crawler': True,
                'is_malicious': False,
                'bot_name': key,
                'threat_weight': 25
            }
            
    # 3. Sprawdź podejrzane narzędzia / headless
    for key, name in SUSPICIOUS_TOOLS.items():
        if key in ua_l:
            is_monitoring = (key in ('zabbix', 'prometheus'))
            return {
                'category': 'SUSPICIOUS_TOOL' if not is_monitoring else 'MONITORING',
                'label': name,
                'is_bot': True,
                'is_crawler': False,
                'is_malicious': not is_monitoring,
                'bot_name': key,
                'threat_weight': 10 if is_monitoring else 90
            }
            
    # Inne ogólne wzorce botów
    if any(b in ua_l for b in ('bot', 'spider', 'crawler', 'scraper', 'checker', 'scan', 'probe')):
        return {
            'category': 'GENERIC_BOT',
            'label': f'Nieznany Bot ({clean_string(ua[:25])})',
            'is_bot': True,
            'is_crawler': True,
            'is_malicious': False,
            'bot_name': 'generic_bot',
            'threat_weight': 40
        }
        
    return {
        'category': 'HUMAN_BROWSER',
        'label': 'Standardowa Przeglądarka',
        'is_bot': False,
        'is_crawler': False,
        'is_malicious': False,
        'bot_name': None,
        'threat_weight': 0
    }

def resolve_city_pl(org: str) -> str:
    """Określa przybliżone miasto / węzeł w Polsce na podstawie operatora."""
    if not org:
        return 'Warszawa'
    org_l = org.lower()
    for key, city in ISP_CITY_MAP.items():
        if key in org_l:
            return city
    # Domyślny główny węzeł wymiany ruchu PL (PLIX / TPIX / Equinix)
    return 'Warszawa'

# ==============================================================================
# OBSŁUGA BIAŁEJ LISTY IP / PODSIECI
# ==============================================================================

class IPWhitelist:
    """Zarządza białą listą adresów IP oraz podsieci CIDR wykluczanych z analizy."""
    def __init__(self, entries=None):
        self.exact_ips = set()
        self.networks = []
        self.raw_entries = []
        if entries:
            for entry in entries:
                self.add(entry)

    def add(self, entry: str):
        if not entry:
            return
        entry = str(entry).strip()
        if not entry or entry.startswith('#'):
            return
        # format: "IP # opis" lub "IP"
        if '#' in entry:
            entry = entry.split('#', 1)[0].strip()
        if not entry:
            return

        self.raw_entries.append(entry)
        try:
            if '/' in entry:
                net = ipaddress.ip_network(entry, strict=False)
                self.networks.append(net)
            else:
                ip_obj = ipaddress.ip_address(entry)
                self.exact_ips.add(str(ip_obj))
        except ValueError:
            self.exact_ips.add(entry)

    def is_whitelisted(self, ip_str: str) -> bool:
        if not ip_str:
            return False
        if ip_str in self.exact_ips:
            return True
        if self.networks:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                for net in self.networks:
                    if ip_obj in net:
                        return True
            except ValueError:
                pass
        return False

    def get_entries(self):
        res = list(self.exact_ips) + [str(n) for n in self.networks]
        return sorted(res)

    def __len__(self):
        return len(self.exact_ips) + len(self.networks)

# ==============================================================================
# PAMIĘĆ PODRĘCZNA (CACHE) I ODKRYWANIE LOGÓW
# ==============================================================================

class LogDataCache:
    """Obsługa pamięci podręcznej (cache w formacie JSON) dla przetworzonych plików logów."""
    def __init__(self, cache_file='.traffic_analyzer_cache.json', enabled=True, clear_cache=False):
        self.cache_file = cache_file
        self.enabled = enabled
        self.entries = {}
        if clear_cache and os.path.exists(self.cache_file):
            try:
                os.remove(self.cache_file)
                print(f"🧹 Wyczyszczono plik pamięci podręcznej: {self.cache_file}")
            except Exception as e:
                print(f"⚠️  Nie udało się usunąć starego cache: {e}")
        elif self.enabled:
            self.load()

    def load(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and data.get('version') == 1:
                        self.entries = data.get('files', {})
            except Exception as e:
                print(f"⚠️  Nie udało się wczytać cache ({self.cache_file}): {e}")
                self.entries = {}

    def save(self):
        if not self.enabled:
            return
        try:
            cache_dir = os.path.dirname(os.path.abspath(self.cache_file))
            if cache_dir and not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'version': 1,
                    'last_updated': datetime.now().isoformat(),
                    'files': self.entries
                }, f, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️  Nie udało się zapisać cache ({self.cache_file}): {e}")

    def get(self, file_path, file_size, file_mtime, filter_date, whitelist_hash, max_lines=None):
        if not self.enabled:
            return None
        abs_p = os.path.abspath(file_path)
        entry = self.entries.get(abs_p) or self.entries.get(file_path)
        if not entry:
            return None
        # Weryfikacja spójności: identyczny rozmiar pliku, mtime, data filtru, hash białej listy, max_lines
        if entry.get('file_size') == file_size and abs(entry.get('file_mtime', 0) - file_mtime) < 0.1:
            if entry.get('filter_date') == filter_date and entry.get('whitelist_hash') == whitelist_hash:
                if entry.get('max_lines') == max_lines:
                    return entry.get('data')
        return None

    def set(self, file_path, file_size, file_mtime, filter_date, whitelist_hash, data, max_lines=None):
        if not self.enabled:
            return
        abs_p = os.path.abspath(file_path)
        self.entries[abs_p] = {
            'file_size': file_size,
            'file_mtime': file_mtime,
            'filter_date': filter_date,
            'whitelist_hash': whitelist_hash,
            'max_lines': max_lines,
            'cached_at': datetime.now().isoformat(),
            'data': data
        }

def discover_log_files(path=None, mask=None, legacy_log_pattern=None):
    """
    Inteligentne wyszukiwanie plików logów dla systemów Linux i Windows.
    - Jeśli podano legacy_log_pattern (-l), wyszukuje wg wzorca glob.
    - Jeśli path jest pojedynczym plikiem, zwraca [path].
    - Jeśli path jest katalogiem, wyszukuje pliki dopasowane do maski.
    - Jeśli domyślny katalog (/var/log/httpd) nie istnieje, sprawdza ścieżki rezerwowe: ./logs, ./ oraz katalog bieżący.
    """
    if legacy_log_pattern and legacy_log_pattern != 'smartsite.mazovia.app-access.log*':
        matched = sorted(glob.glob(os.path.expanduser(legacy_log_pattern)))
        if matched:
            return matched

    target_path = os.path.expanduser(path or '/var/log/httpd')
    file_mask = mask or 'smartsite.mazovia.app-access.log*'

    # Jeśli podano bezpośrednio plik
    if os.path.isfile(target_path):
        return [target_path]

    # Jeśli domyślny katalog /var/log/httpd nie istnieje, szukaj w fallbackach
    if not os.path.exists(target_path) and (path is None or path == '/var/log/httpd'):
        for fallback in ['./logs', '.', os.path.dirname(os.path.abspath(__file__))]:
            if os.path.isdir(fallback):
                candidates = [
                    os.path.join(fallback, f) for f in os.listdir(fallback)
                    if fnmatch.fnmatch(f, file_mask) and os.path.isfile(os.path.join(fallback, f))
                ]
                if candidates:
                    target_path = fallback
                    break

    if not os.path.exists(target_path):
        # Sprawdź czy sama ścieżka nie jest wzorcem glob
        glob_matched = sorted(glob.glob(target_path))
        if glob_matched:
            return glob_matched
        print(f"⚠️  Wskazany katalog logów nie istnieje: {target_path}")
        return []

    if os.path.isdir(target_path):
        found = []
        for root_dir, _, filenames in os.walk(target_path):
            for fname in filenames:
                if fnmatch.fnmatch(fname, file_mask):
                    found.append(os.path.join(root_dir, fname))
            if '**' not in file_mask:
                break
        return sorted(found)

    return []

# ==============================================================================
# GŁÓWNY SILNIK ANALIZY
# ==============================================================================

class WebTrafficAnalyzer:
    def __init__(self, log_path='/var/log/httpd', log_mask='smartsite.mazovia.app-access.log*',
                 log_pattern=None, country_db='GeoLite2-Country.mmdb', asn_db='GeoLite2-ASN.mmdb',
                 url_threshold_mult=2.0, ip_threshold_mult=2.0, min_url_threshold=20, min_ip_threshold=20,
                 filter_date=None, max_lines=None, whitelist=None,
                 cache_file='.traffic_analyzer_cache.json', use_cache=True, clear_cache=False):
        self.log_path = log_path
        self.log_mask = log_mask
        self.log_pattern = log_pattern
        self.geo = GeoResolver(country_db, asn_db)
        self.url_threshold_mult = url_threshold_mult
        self.ip_threshold_mult = ip_threshold_mult
        self.min_url_threshold = min_url_threshold
        self.min_ip_threshold = min_ip_threshold
        self.filter_date = filter_date
        self.max_lines = max_lines
        
        # Pamięć podręczna (cache)
        self.cache = LogDataCache(cache_file=cache_file, enabled=use_cache, clear_cache=clear_cache)
        
        # Konfiguracja białej listy IP
        self.whitelist = IPWhitelist(DEFAULT_WHITELIST_IPS)
        if whitelist:
            if isinstance(whitelist, (list, set, tuple)):
                for item in whitelist:
                    self.whitelist.add(item)
            elif isinstance(whitelist, str):
                for item in whitelist.split(','):
                    if item.strip():
                        self.whitelist.add(item.strip())
        
        # Statystyki globalne
        self.total_lines = 0
        self.processed_lines = 0
        self.whitelisted_requests = 0
        self.whitelisted_ip_counts = Counter()
        self.static_requests = 0
        self.page_requests = 0
        self.status_counter = Counter()
        self.hourly_counter = Counter()
        self.date_counter = Counter()
        
        # Faza 1: Zliczanie URL i sekcji (bez zasobów statycznych)
        self.url_counter = Counter()
        self.section_counter = Counter()
        self.url_status_counter = defaultdict(Counter)
        
        # Mapowanie URL/sekcja -> IP -> liczba żądań
        self.url_ip_map = defaultdict(Counter)
        self.section_ip_map = defaultdict(Counter)
        
        # Statystyki per IP
        self.ip_total_requests = Counter()
        self.ip_page_requests = Counter()
        self.ip_static_requests = Counter()
        self.ip_status_counter = defaultdict(Counter)
        self.ip_urls_map = defaultdict(set)
        self.ip_user_agents = defaultdict(Counter)
        self.ip_first_seen = {}
        self.ip_last_seen = {}
        
        # Progi wyznaczone dynamicznie
        self.url_median = 0
        self.url_threshold = 0
        self.section_median = 0
        self.section_threshold = 0
        self.ip_median = 0
        self.ip_threshold = 0
        
        # Wyniki fazy 2 i 3
        self.exceeded_urls = []
        self.exceeded_sections = []
        self.exceeded_ips = []
        self.suspected_bots_to_block = []
        self.ips_to_blacklist = []
        self.diagnosis = {}

    def parse_log_line(self, line: str):
        """Super-szybki parser standardowego formatu logów Apache Combined bez wolnych wyrażeń regularnych."""
        try:
            parts = line.split('"')
            if len(parts) < 2:
                return None
            
            p0 = parts[0]
            ip = p0.split(' ', 1)[0]
            
            b1 = p0.find('[')
            b2 = p0.find(']', b1)
            time_str = p0[b1 + 1:b2] if (b1 != -1 and b2 != -1) else ""
            
            req = parts[1].split(' ')
            if len(req) < 2:
                return None
            method = req[0]
            raw_url = req[1]
            
            status_code = parts[2].strip().split(' ', 1)[0] if len(parts) > 2 else "200"
            referer = parts[3] if len(parts) > 3 else "-"
            user_agent = parts[5] if len(parts) > 5 else "-"
            
            return {
                'ip': ip,
                'time_str': time_str,
                'method': method,
                'url': raw_url,
                'status': status_code,
                'referer': referer,
                'user_agent': user_agent
            }
        except Exception:
            return None

    def _process_single_file(self, file_path: str):
        """
        Przetwarza pojedynczy plik logu z uwzględnieniem:
        1. Snapshotu rozmiaru pliku w momencie startu (ochrona przed ciągłym dopisywaniem na żywym serwerze).
        2. Sprawdzenia pamięci podręcznej (cache) w formacie JSON.
        3. Obsługi skompresowanych archiwów logów (.gz).
        """
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            file_mtime = stat.st_mtime
        except Exception as e:
            print(f"  ❌ Błąd odczytu atrybutów pliku {file_path}: {e}")
            return None

        whitelist_entries = sorted(self.whitelist.get_entries())
        whitelist_hash = hashlib.md5(json.dumps(whitelist_entries).encode()).hexdigest()

        # 1. Próba pobrania z cache
        cached_data = self.cache.get(file_path, file_size, file_mtime, self.filter_date, whitelist_hash, self.max_lines)
        if cached_data is not None:
            cached_lines = cached_data.get('total_lines', 0)
            cached_proc = cached_data.get('processed_lines', 0)
            print(f"  ⚡ [CACHE HIT] Wczytano z pamięci podręcznej: {file_path} ({cached_lines:,} linii, {cached_proc:,} przetworzonych)")
            return cached_data

        size_mb = file_size / (1024 * 1024)
        print(f"  🔄 Przetwarzanie z dysku: {file_path} (rozmiar w momencie startu: {size_mb:.2f} MB)")

        is_gz = file_path.endswith('.gz')
        open_func = gzip.open if is_gz else open

        file_data = {
            'total_lines': 0,
            'processed_lines': 0,
            'whitelisted_requests': 0,
            'whitelisted_ip_counts': {},
            'static_requests': 0,
            'page_requests': 0,
            'status_counter': {},
            'hourly_counter': {},
            'date_counter': {},
            'url_counter': {},
            'section_counter': {},
            'url_status_counter': {},
            'url_ip_map': {},
            'section_ip_map': {},
            'ip_total_requests': {},
            'ip_page_requests': {},
            'ip_static_requests': {},
            'ip_status_counter': {},
            'ip_user_agents': {},
            'ip_first_seen': {},
            'ip_last_seen': {}
        }

        tot_lines = 0
        proc_lines = 0
        wl_reqs = 0
        wl_ip_counts = Counter()
        stat_reqs = 0
        page_reqs = 0
        st_counter = Counter()
        hr_counter = Counter()
        dt_counter = Counter()
        u_counter = Counter()
        sec_counter = Counter()
        u_st_counter = defaultdict(Counter)
        u_ip_map = defaultdict(Counter)
        sec_ip_map = defaultdict(Counter)
        ip_tot = Counter()
        ip_pg = Counter()
        ip_st = Counter()
        ip_st_counter = defaultdict(Counter)
        ip_uas = defaultdict(Counter)
        ip_first = {}
        ip_last = {}

        try:
            with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                while True:
                    # Ochrona przed czytaniem w nieskończoność na żywym serwerze:
                    # nie czytamy bajtów dopisanych po snapshotowaniu rozmiaru pliku
                    if not is_gz:
                        try:
                            if f.tell() > file_size:
                                break
                        except Exception:
                            pass

                    line = f.readline()
                    if not line:
                        break

                    tot_lines += 1
                    if self.max_lines and tot_lines > self.max_lines:
                        break

                    entry = self.parse_log_line(line)
                    if not entry:
                        continue

                    time_str = entry['time_str']
                    try:
                        date_part = time_str.split(':')[0]
                        hour_part = ':'.join(time_str.split(':')[:2])
                    except Exception:
                        date_part = time_str
                        hour_part = time_str

                    if self.filter_date and self.filter_date != 'all' and date_part != self.filter_date:
                        continue

                    ip = entry['ip']
                    if self.whitelist.is_whitelisted(ip):
                        wl_reqs += 1
                        wl_ip_counts[ip] += 1
                        continue

                    proc_lines += 1
                    status = entry['status']
                    st_counter[status] += 1
                    hr_counter[hour_part] += 1
                    dt_counter[date_part] += 1

                    raw_url = entry['url']
                    url_clean = raw_url.split('?')[0]
                    ua = entry['user_agent']

                    ip_tot[ip] += 1
                    ip_st_counter[ip][status] += 1
                    ip_uas[ip][ua] += 1

                    if ip not in ip_first:
                        ip_first[ip] = time_str
                    ip_last[ip] = time_str

                    if is_static_resource(url_clean):
                        stat_reqs += 1
                        ip_st[ip] += 1
                        continue

                    page_reqs += 1
                    ip_pg[ip] += 1
                    u_counter[url_clean] += 1
                    u_st_counter[url_clean][status] += 1

                    sec = extract_section(url_clean)
                    sec_counter[sec] += 1

                    u_ip_map[url_clean][ip] += 1
                    sec_ip_map[sec][ip] += 1

        except Exception as e:
            print(f"  ❌ Błąd podczas przetwarzania pliku {file_path}: {e}")
            return None

        file_data['total_lines'] = tot_lines
        file_data['processed_lines'] = proc_lines
        file_data['whitelisted_requests'] = wl_reqs
        file_data['whitelisted_ip_counts'] = dict(wl_ip_counts)
        file_data['static_requests'] = stat_reqs
        file_data['page_requests'] = page_reqs
        file_data['status_counter'] = dict(st_counter)
        file_data['hourly_counter'] = dict(hr_counter)
        file_data['date_counter'] = dict(dt_counter)
        file_data['url_counter'] = dict(u_counter)
        file_data['section_counter'] = dict(sec_counter)
        file_data['url_status_counter'] = {u: dict(c) for u, c in u_st_counter.items()}
        file_data['url_ip_map'] = {u: dict(c) for u, c in u_ip_map.items()}
        file_data['section_ip_map'] = {s: dict(c) for s, c in sec_ip_map.items()}
        file_data['ip_total_requests'] = dict(ip_tot)
        file_data['ip_page_requests'] = dict(ip_pg)
        file_data['ip_static_requests'] = dict(ip_st)
        file_data['ip_status_counter'] = {ip: dict(c) for ip, c in ip_st_counter.items()}
        file_data['ip_user_agents'] = {ip: dict(c) for ip, c in ip_uas.items()}
        file_data['ip_first_seen'] = ip_first
        file_data['ip_last_seen'] = ip_last

        # Zapisz do pamięci podręcznej dla tego pliku
        self.cache.set(file_path, file_size, file_mtime, self.filter_date, whitelist_hash, file_data, self.max_lines)
        return file_data

    def _merge_file_data(self, file_data: dict):
        """Scalanie statystyk z pojedynczego pliku do stanu globalnego analizatora."""
        self.total_lines += file_data.get('total_lines', 0)
        self.processed_lines += file_data.get('processed_lines', 0)
        self.whitelisted_requests += file_data.get('whitelisted_requests', 0)
        self.whitelisted_ip_counts.update(file_data.get('whitelisted_ip_counts', {}))
        self.static_requests += file_data.get('static_requests', 0)
        self.page_requests += file_data.get('page_requests', 0)
        self.status_counter.update(file_data.get('status_counter', {}))
        self.hourly_counter.update(file_data.get('hourly_counter', {}))
        self.date_counter.update(file_data.get('date_counter', {}))
        self.url_counter.update(file_data.get('url_counter', {}))
        self.section_counter.update(file_data.get('section_counter', {}))

        for u, st_map in file_data.get('url_status_counter', {}).items():
            self.url_status_counter[u].update(st_map)

        for u, ip_map in file_data.get('url_ip_map', {}).items():
            self.url_ip_map[u].update(ip_map)

        for sec, ip_map in file_data.get('section_ip_map', {}).items():
            self.section_ip_map[sec].update(ip_map)

        self.ip_total_requests.update(file_data.get('ip_total_requests', {}))
        self.ip_page_requests.update(file_data.get('ip_page_requests', {}))
        self.ip_static_requests.update(file_data.get('ip_static_requests', {}))

        for ip, st_map in file_data.get('ip_status_counter', {}).items():
            self.ip_status_counter[ip].update(st_map)

        for ip, ua_map in file_data.get('ip_user_agents', {}).items():
            self.ip_user_agents[ip].update(ua_map)

        for ip, fs in file_data.get('ip_first_seen', {}).items():
            if ip not in self.ip_first_seen or fs < self.ip_first_seen[ip]:
                self.ip_first_seen[ip] = fs

        for ip, ls in file_data.get('ip_last_seen', {}).items():
            if ip not in self.ip_last_seen or ls > self.ip_last_seen[ip]:
                self.ip_last_seen[ip] = ls

    def run_analysis(self):
        """Wykonanie pełnego potoku analizy."""
        log_files = discover_log_files(
            path=self.log_path,
            mask=self.log_mask,
            legacy_log_pattern=self.log_pattern
        )
        if not log_files:
            target_desc = self.log_pattern if self.log_pattern else f"ścieżka='{self.log_path}', maska='{self.log_mask}'"
            print(f"❌ Błąd: Nie znaleziono plików logów pasujących do kryteriów: {target_desc}")
            return False

        print(f"🔍 Rozpoczynam analizę {len(log_files)} plik(ów) logów...")
        processed_files = 0
        
        for file_path in log_files:
            file_data = self._process_single_file(file_path)
            if file_data:
                self._merge_file_data(file_data)
                processed_files += 1

        # Zapisanie zaktualizowanego stanu pamięci podręcznej do pliku JSON
        self.cache.save()

        if processed_files == 0 or self.total_lines == 0:
            print("⚠️  Nie wczytano żadnych wpisów z plików logów.")
            return False

        print(f"✅ Przetworzono łącznie {self.processed_lines:,} wpisów (w tym {self.page_requests:,} żądań stron, {self.static_requests:,} statycznych).")
        if self.whitelisted_requests > 0:
            top_wh = ', '.join([f'{ip} ({cnt:,})' for ip, cnt in self.whitelisted_ip_counts.most_common(3)])
            print(f"🛡️  Wykluczono z analizy (Biała lista): {self.whitelisted_requests:,} żądań z {len(self.whitelisted_ip_counts)} IP [{top_wh}].")
        
        # Obliczenie progów i klasyfikacja
        self._calculate_thresholds()
        self._analyze_exceeded_targets()
        self._classify_and_diagnose()
        return True

    def _calculate_thresholds(self):
        """KROK 1: Wyznaczenie progu nadmiernego ruchu na URL i sekcje (2 * mediana)."""
        url_counts = list(self.url_counter.values())
        if url_counts:
            self.url_median = float(np.median(url_counts))
            calc_thresh = self.url_median * self.url_threshold_mult
            # Próg to max(2*mediana, min_url_threshold) aby uniknąć fałszywych alarmów przy niskim ruchu
            self.url_threshold = max(calc_thresh, float(self.min_url_threshold))
        else:
            self.url_median = 0
            self.url_threshold = self.min_url_threshold

        sec_counts = list(self.section_counter.values())
        if sec_counts:
            self.section_median = float(np.median(sec_counts))
            calc_sec_thresh = self.section_median * self.url_threshold_mult
            self.section_threshold = max(calc_sec_thresh, float(self.min_url_threshold * 2))
        else:
            self.section_median = 0
            self.section_threshold = self.min_url_threshold * 2

        print(f"📊 Progi URL/Sekcje: Mediana URL = {self.url_median:.1f} -> Próg URL = {self.url_threshold:.1f} | Mediana Sekcji = {self.section_median:.1f} -> Próg Sekcji = {self.section_threshold:.1f}")

    def _analyze_exceeded_targets(self):
        """KROK 2: Sprawdzenie jakie IP odpytywały przekroczone URL-e i wyznaczenie anomalnych IP."""
        # 1. URL-e przekraczające próg
        for url, count in self.url_counter.items():
            if count >= self.url_threshold:
                self.exceeded_urls.append({
                    'url': url,
                    'section': extract_section(url),
                    'count': count,
                    'unique_ips': len(self.url_ip_map[url]),
                    'status_500': self.url_status_counter[url]['500'],
                    'status_403': self.url_status_counter[url]['403'],
                    'status_200': self.url_status_counter[url]['200']
                })
        self.exceeded_urls.sort(key=lambda x: x['count'], reverse=True)

        # 2. Sekcje przekraczające próg
        for sec, count in self.section_counter.items():
            if count >= self.section_threshold:
                self.exceeded_sections.append({
                    'section': sec,
                    'count': count,
                    'unique_ips': len(self.section_ip_map[sec])
                })
        self.exceeded_sections.sort(key=lambda x: x['count'], reverse=True)

        # 3. Zbiór IP odpytujących przekroczone URL-e
        hot_ips = Counter()
        for item in self.exceeded_urls:
            url = item['url']
            for ip, c in self.url_ip_map[url].items():
                hot_ips[ip] += c

        # Obliczenie progu dla IP (2 * mediana żądań IP)
        ip_counts = [self.ip_page_requests[ip] for ip in hot_ips.keys()]
        if ip_counts:
            self.ip_median = float(np.median(ip_counts))
            calc_ip_thresh = self.ip_median * self.ip_threshold_mult
            self.ip_threshold = max(calc_ip_thresh, float(self.min_ip_threshold))
        else:
            self.ip_median = 0
            self.ip_threshold = self.min_ip_threshold

        print(f"📊 Progi IP: Mediana IP = {self.ip_median:.1f} -> Próg anomalnego IP = {self.ip_threshold:.1f}")

        # 4. Szczegółowa analiza i geolokalizacja IP ponad progiem
        for ip, hot_count in hot_ips.items():
            total_reqs = self.ip_total_requests[ip]
            page_reqs = self.ip_page_requests[ip]
            if page_reqs < self.ip_threshold:
                continue

            geo_c = self.geo.get_country(ip)
            geo_a = self.geo.get_asn(ip)
            
            # Analiza User-Agentów tego IP
            uas = self.ip_user_agents[ip]
            top_ua, top_ua_count = uas.most_common(1)[0] if uas else ("-", 0)
            ua_class = classify_user_agent(top_ua)
            
            # Wskaźnik pobierania statyków (stosunek static / pages)
            static_reqs = self.ip_static_requests[ip]
            static_ratio = static_reqs / (page_reqs + 1e-6)
            
            # Błędy
            err_500 = self.ip_status_counter[ip]['500']
            err_403 = self.ip_status_counter[ip]['403']
            err_429 = self.ip_status_counter[ip]['429']
            total_err = err_500 + err_403 + err_429
            err_rate = (total_err / total_reqs) * 100 if total_reqs else 0
            
            # Obliczenie wskaźnika zagrożenia (Threat Score 0-100)
            threat_score = 0
            reasons = []
            
            if ua_class['is_malicious']:
                threat_score += 45
                reasons.append(f"Podejrzany User-Agent ({ua_class['label']})")
            elif ua_class['is_bot'] and not ua_class['is_crawler']:
                threat_score += 25
                reasons.append("Narzędzie automatyzacji / skrypt")
                
            # Brak pobierania zasobów statycznych (typowe dla botów i crawlerów)
            if page_reqs > 50 and static_ratio < 0.05:
                threat_score += 25
                reasons.append("Brak pobierania zasobów graficznych/CSS/JS (czysty scraping/atak)")
                
            # Wysoki odsetek błędów serwera generowanych przez dane IP
            if err_rate > 15:
                threat_score += 20
                reasons.append(f"Wysoki odsetek błędów {err_rate:.1f}% (500/403/429)")
                
            # Zagraniczne centra danych / serwery chmurowe (DigitalOcean, AWS, Hetzner itp.)
            org_l = geo_a['org'].lower()
            if any(cloud in org_l for cloud in ('amazon', 'aws', 'google-cloud', 'digitalocean', 'hetzner', 'ovh', 'linode', 'alibaba', 'tencent', 'microsoft-corp', 'm247', 'host', 'datacenter', 'vultr')):
                if not ua_class['is_crawler']:
                    threat_score += 20
                    reasons.append(f"IP z centrum danych/chmury ({geo_a['org']})")

            threat_score = min(threat_score, 100)
            
            # Sprawdzenie czy IP jest prywatne / lokalne
            is_internal = False
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                    is_internal = True
            except ValueError:
                pass

            # Klasyfikacja typu ruchu z danego IP
            if is_internal or ua_class['category'] == 'MONITORING':
                ip_type = 'MONITORING'
                badge_class = 'badge-secondary'
                threat_score = 0
            elif ua_class['category'] == 'SEARCH_BOT':
                ip_type = 'SEARCH_ENGINE'
                badge_class = 'badge-info'
            elif threat_score >= 50 or ua_class['is_malicious']:
                ip_type = 'ATTACKER'
                badge_class = 'badge-danger'
                if not is_internal:
                    self.ips_to_blacklist.append(ip)
            elif ua_class['category'] in ('SEO_AI_BOT', 'GENERIC_BOT'):
                ip_type = 'SCRAPER_BOT'
                badge_class = 'badge-warning'
            else:
                ip_type = 'SUSPICIOUS_HEAVY_USER' if threat_score >= 30 else 'LEGITIMATE_USER'
                badge_class = 'badge-primary' if threat_score < 30 else 'badge-warning'

            # Miasto dla ruchu PL
            city_pl = resolve_city_pl(geo_a['org']) if geo_c['code'] == 'PL' else None

            self.exceeded_ips.append({
                'ip': ip,
                'country_code': geo_c['code'],
                'country_name': geo_c['name_pl'],
                'country_en': geo_c['name_en'],
                'asn': f"AS{geo_a['asn']}" if geo_a['asn'] else 'N/A',
                'isp': geo_a['org'],
                'city_pl': city_pl,
                'total_requests': total_reqs,
                'page_requests': page_reqs,
                'static_requests': static_reqs,
                'hot_url_requests': hot_count,
                'status_500': err_500,
                'status_403': err_403,
                'error_rate': round(err_rate, 1),
                'top_ua': top_ua,
                'ua_label': ua_class['label'],
                'ua_category': ua_class['category'],
                'bot_name': ua_class['bot_name'],
                'threat_score': threat_score,
                'threat_reasons': reasons,
                'traffic_type': ip_type,
                'badge_class': badge_class
            })

        self.exceeded_ips.sort(key=lambda x: x['page_requests'], reverse=True)

    def _classify_and_diagnose(self):
        """KROK 3: Ocena i diagnoza charakteru ruchu (Atak vs Indeksowanie vs Normalny ruch)."""
        total_p = self.page_requests or 1
        
        # Zliczanie według kategorii
        counts_by_type = Counter(item['traffic_type'] for item in self.exceeded_ips)
        reqs_by_type = Counter()
        for item in self.exceeded_ips:
            reqs_by_type[item['traffic_type']] += item['page_requests']
            
        attacker_reqs = reqs_by_type['ATTACKER']
        search_reqs = reqs_by_type['SEARCH_ENGINE']
        scraper_reqs = reqs_by_type['SCRAPER_BOT']
        user_reqs = reqs_by_type['LEGITIMATE_USER'] + reqs_by_type['SUSPICIOUS_HEAVY_USER']
        
        err_500_total = self.status_counter['500']
        err_500_pct = (err_500_total / self.processed_lines) * 100 if self.processed_lines else 0
        
        # Wykrywanie botów do reguł Apache
        blocked_uas = set()
        for item in self.exceeded_ips:
            if item['traffic_type'] in ('ATTACKER', 'SCRAPER_BOT') and item['bot_name']:
                if item['bot_name'] != 'Empty User-Agent':
                    blocked_uas.add(item['bot_name'])
        self.suspected_bots_to_block = sorted(list(blocked_uas))

        # Werdykt
        verdict = ""
        verdict_badge = ""
        confidence = "Wysoka"
        summary_points = []
        
        # Logika decyzyjna
        is_attack = False
        is_crawler = False
        is_normal = False
        
        if attacker_reqs > (0.25 * total_p) or err_500_pct > 3.0 or len(self.ips_to_blacklist) > 5:
            is_attack = True
        elif search_reqs > (0.40 * total_p):
            is_crawler = True
        else:
            is_normal = True
            
        if is_attack:
            verdict = "Ruch ze względu na Atak DDoS / Działanie Botnetu i Agresywny Scraping"
            verdict_badge = "ATTACK_DETECTED"
            summary_points.append(f"Wykryto zmasowany, zautomatyzowany ruch generujący wysokie obciążenie serwera i błędy HTTP 500 ({err_500_total:,} błędów, {err_500_pct:.1f}% całości ruchu).")
            summary_points.append(f"Zidentyfikowano {len(self.ips_to_blacklist):,} adresów IP o wysokim wskaźniku zagrożenia (narzędzia automatyzacji HeadlessChrome, skrypty, zapytania z chmur obliczeniowych bez pobierania assetów).")
            summary_points.append("Wymagana natychmiastowa blokada wytypowanych IP w zaporze sieciowej (iptables) oraz zablokowanie sygnatur botów w konfiguracji Apache.")
        elif is_crawler:
            verdict = "Ruch ze względu na Intensywne Indeksowanie przez Wyszukiwarki"
            verdict_badge = "SEARCH_INDEXING"
            summary_points.append("Dominujący wolumen ruchu pochodzi ze zweryfikowanych robotów indeksujących (np. Googlebot, Bingbot, Yandex).")
            summary_points.append("Wskaźnik błędów serwera 500 jest na niskim poziomie; zapytania równomiernie penetrują strukturę serwisu.")
            summary_points.append("Zaleca się optymalizację dyrektyw w `robots.txt` (np. Crawl-delay lub wykluczenie zbędnych parametrów).")
        else:
            verdict = "Zwiększony, ale Normalny Ruch Użytkowników (np. Kampania Informacyjna / Zainteresowanie Treściami)"
            verdict_badge = "NORMAL_SURGE"
            summary_points.append("Ruch pochodzi w większości od standardowych przeglądarek z polskich dostawców internetu (Orange, Play, T-Mobile, Netia itp.).")
            summary_points.append("Występuje naturalny stosunek pobierania stron do zasobów statycznych (CSS, grafiki, skrypty JS).")
            summary_points.append("Brak cech skoordynowanego ataku botnetu; ewentualne spowolnienia wynikają z naturalnego skoku popularności.")

        if self.whitelisted_requests > 0:
            entries_str = ', '.join(self.whitelist.get_entries())
            summary_points.append(f"Zgodnie z konfiguracją, całkowicie wykluczono z analizy {self.whitelisted_requests:,} żądań pochodzących ze zdefiniowanej białej listy IP ({entries_str}).")

        self.diagnosis = {
            'verdict': verdict,
            'badge': verdict_badge,
            'confidence': confidence,
            'summary_points': summary_points,
            'attacker_reqs': attacker_reqs,
            'search_reqs': search_reqs,
            'scraper_reqs': scraper_reqs,
            'user_reqs': user_reqs,
            'err_500_pct': round(err_500_pct, 2),
            'err_500_count': err_500_total,
            'unique_ips_total': len(self.ip_total_requests),
            'blacklist_count': len(self.ips_to_blacklist),
            'blocked_bots_count': len(self.suspected_bots_to_block),
            'whitelisted_requests': self.whitelisted_requests,
            'whitelisted_ips_count': len(self.whitelisted_ip_counts),
            'whitelisted_entries': self.whitelist.get_entries()
        }

    def generate_blacklist_file(self, output_path='blacklist_ips.txt'):
        """Zapis listy IP do zablokowania."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# ==========================================================\n")
            f.write(f"# Web Traffic Analyzer - Blacklist IP generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Liczba adresów IP do zablokowania: {len(self.ips_to_blacklist)}\n")
            f.write("# ==========================================================\n\n")
            for ip in sorted(self.ips_to_blacklist):
                f.write(f"{ip}\n")
        print(f"📁 Zapisano listę IP do zablokowania: {output_path} ({len(self.ips_to_blacklist)} adresów)")

    def generate_apache_rules_file(self, output_path='apache_block_rules.conf'):
        """Zapis reguł Apache blokujących boty i złośliwe IP."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# ==========================================================\n")
            f.write(f"# Apache 2.4 Security Rules - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Wklej poniższe reguły do pliku .htaccess lub sekcji <VirtualHost> / <Directory>\n")
            f.write("# ==========================================================\n\n")
            
            f.write("# 1. Blokowanie złośliwych User-Agentów i agresywnych scraperów\n")
            f.write("<IfModule mod_setenvif.c>\n")
            for bot in self.suspected_bots_to_block:
                f.write(f'    SetEnvIfNoCase User-Agent "{bot}" bad_bot=1\n')
            f.write('    SetEnvIfNoCase User-Agent "^$" bad_bot=1\n')
            f.write("</IfModule>\n\n")
            
            f.write("# 2. Wymuszenie odmowy dostępu dla zablokowanych botów oraz IP\n")
            f.write("<RequireAll>\n")
            f.write("    Require all granted\n")
            f.write("    Require not env bad_bot\n")
            for ip in sorted(self.ips_to_blacklist)[:500]: # max 500 do conf
                f.write(f"    Require not ip {ip}\n")
            f.write("</RequireAll>\n\n")
            
            f.write("# 3. Opcjonalne reguły mod_rewrite (zwraca HTTP 403 Forbidden)\n")
            f.write("<IfModule mod_rewrite.c>\n")
            f.write("    RewriteEngine On\n")
            if self.suspected_bots_to_block:
                cond = '|'.join(re.escape(b) for b in self.suspected_bots_to_block)
                f.write(f'    RewriteCond %{{HTTP_USER_AGENT}} ({cond}) [NC,OR]\n')
            f.write('    RewriteCond %{HTTP_USER_AGENT} ^$ [OR]\n')
            f.write('    RewriteCond %{HTTP_USER_AGENT} (headlesschrome|sqlmap|nikto) [NC]\n')
            f.write('    RewriteRule .* - [F,L]\n')
            f.write("</IfModule>\n")
        print(f"📁 Zapisano reguły Apache: {output_path}")

    def generate_html_report(self, output_path='traffic_analysis_report.html'):
        """Generowanie nowoczesnego raportu HTML z mapami Leaflet, wykresami Chart.js i DataTables."""
        # Przygotowanie danych do mapy krajów
        country_agg = defaultdict(lambda: {'count': 0, 'code': '', 'name_pl': '', 'attack_count': 0})
        for item in self.exceeded_ips:
            c_name = item['country_name']
            country_agg[c_name]['count'] += item['page_requests']
            country_agg[c_name]['code'] = item['country_code']
            country_agg[c_name]['name_pl'] = c_name
            if item['traffic_type'] == 'ATTACKER':
                country_agg[c_name]['attack_count'] += item['page_requests']

        map_countries_data = []
        for c_name, data in country_agg.items():
            coords = COUNTRY_COORDS.get(c_name, COUNTRY_COORDS.get(data['code'], [20.0, 0.0]))
            map_countries_data.append({
                'name': c_name,
                'code': data['code'],
                'lat': coords[0],
                'lng': coords[1],
                'requests': data['count'],
                'attack_requests': data['attack_count']
            })

        # Przygotowanie danych do mapy miast Polski
        city_agg = Counter()
        city_attack_agg = Counter()
        for item in self.exceeded_ips:
            if item['country_code'] == 'PL' and item['city_pl']:
                city = item['city_pl']
                city_agg[city] += item['page_requests']
                if item['traffic_type'] == 'ATTACKER':
                    city_attack_agg[city] += item['page_requests']

        map_pl_cities_data = []
        for city, reqs in city_agg.items():
            coords = POLISH_CITIES_COORDS.get(city, [52.2297, 21.0122])
            map_pl_cities_data.append({
                'city': city,
                'lat': coords[0],
                'lng': coords[1],
                'requests': reqs,
                'attack_requests': city_attack_agg[city]
            })

        # Wykres godzinowy
        sorted_hours = sorted(self.hourly_counter.items())
        chart_timeline_labels = [h[0] for h in sorted_hours]
        chart_timeline_values = [h[1] for h in sorted_hours]

        # Wykres kodów statusu
        chart_status_labels = [str(k) for k, v in self.status_counter.most_common(8)]
        chart_status_values = [v for k, v in self.status_counter.most_common(8)]

        # Wykres klasyfikacji ruchu
        diag = self.diagnosis
        chart_type_labels = ['Atak / Złośliwe Boty', 'Wyszukiwarki (SEO)', 'Agresywne Scrapery', 'Użytkownicy / Normalny']
        chart_type_values = [diag['attacker_reqs'], diag['search_reqs'], diag['scraper_reqs'], diag['user_reqs']]

        # Top 10 Krajów do wykresu
        top_countries = sorted(country_agg.items(), key=lambda x: x[1]['count'], reverse=True)[:8]
        chart_countries_labels = [c[0] for c in top_countries]
        chart_countries_values = [c[1]['count'] for c in top_countries]

        # Top 10 Operatorów ASN
        asn_counter = Counter()
        for item in self.exceeded_ips:
            asn_counter[item['isp']] += item['page_requests']
        top_asns = asn_counter.most_common(8)
        chart_asn_labels = [clean_string(a[0][:25]) for a in top_asns]
        chart_asn_values = [a[1] for a in top_asns]

        # Generowanie HTML
        html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer-when-downgrade">
    <title>Raport Analizy Ruchu WWW i Detekcji DDoS / Botów</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous" referrerpolicy="no-referrer">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
    <!-- Leaflet Map CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <!-- DataTables CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/datatables.net-bs5/1.13.6/dataTables.bootstrap5.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/datatables.net-buttons-bs5/2.4.2/buttons.bootstrap5.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet" crossorigin="anonymous">
    <style>
        body {{
            font-family: 'Inter', sans-serif;
            background-color: #f4f6f9;
            color: #2c3e50;
        }}
        .navbar-brand {{
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .card {{
            border-radius: 12px;
            border: none;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            margin-bottom: 24px;
            transition: transform 0.2s ease;
        }}
        .card-header {{
            background-color: #ffffff;
            border-bottom: 1px solid #edf2f7;
            font-weight: 600;
            border-top-left-radius: 12px !important;
            border-top-right-radius: 12px !important;
            padding: 16px 20px;
        }}
        .kpi-card {{
            border-left: 4px solid #3b82f6;
        }}
        .kpi-card.danger {{
            border-left-color: #ef4444;
        }}
        .kpi-card.warning {{
            border-left-color: #f59e0b;
        }}
        .kpi-card.success {{
            border-left-color: #10b981;
        }}
        .kpi-number {{
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        .kpi-label {{
            font-size: 13px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .verdict-banner {{
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            color: #ffffff;
        }}
        .verdict-banner.ATTACK_DETECTED {{
            background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
        }}
        .verdict-banner.SEARCH_INDEXING {{
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        }}
        .verdict-banner.NORMAL_SURGE {{
            background: linear-gradient(135deg, #10b981 0%, #047857 100%);
        }}
        #worldMap, #polandMap {{
            height: 480px;
            border-radius: 8px;
            width: 100%;
        }}
        .chart-container-timeline {{
            position: relative;
            height: 200px;
            max-height: 200px;
            width: 100%;
        }}
        .chart-container-pie {{
            position: relative;
            height: 200px;
            max-height: 200px;
            width: 100%;
        }}
        .chart-container-bar {{
            position: relative;
            height: 200px;
            max-height: 200px;
            width: 100%;
        }}
        .badge-danger {{ background-color: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }}
        .badge-warning {{ background-color: #fef3c7; color: #b45309; border: 1px solid #fde68a; }}
        .badge-info {{ background-color: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }}
        .badge-primary {{ background-color: #e0e7ff; color: #4338ca; border: 1px solid #c7d2fe; }}
        .badge-secondary {{ background-color: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }}
        pre.code-block {{
            background: #1e293b;
            color: #f8fafc;
            padding: 16px;
            border-radius: 8px;
            font-size: 13px;
            max-height: 320px;
            overflow-y: auto;
        }}
        .btn-copy {{
            position: absolute;
            top: 12px;
            right: 12px;
        }}
        .table-responsive {{
            border-radius: 8px;
        }}
    </style>
</head>
<body>

    <!-- Nawigacja -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
        <div class="container-fluid px-4">
            <a class="navbar-brand" href="#">
                <i class="fa-solid fa-shield-halved text-danger me-2"></i>
                Web Traffic & DDoS Analyzer
            </a>
            <span class="navbar-text text-light opacity-75 small">
                Data generowania: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong> | Host: <strong>{socket.gethostname()}</strong>
            </span>
        </div>
    </nav>

    <div class="container-fluid px-4 py-4">

        <!-- Baner Główny Werdyktu -->
        <div class="verdict-banner {diag['badge']}">
            <div class="d-flex align-items-center mb-2">
                <i class="fa-solid {'fa-triangle-exclamation' if diag['badge']=='ATTACK_DETECTED' else ('fa-robot' if diag['badge']=='SEARCH_INDEXING' else 'fa-circle-check')} fa-2x me-3"></i>
                <h3 class="mb-0 fw-bold">{diag['verdict']}</h3>
            </div>
            <p class="mb-3 opacity-90 fs-6">Pewność oceny: <strong>{diag['confidence']}</strong> | Analiza heurystyczna na podstawie rozkładu IP, User-Agent, statusów 500 oraz stosunku zapytań dynamicznych do statycznych.</p>
            <div class="bg-white bg-opacity-10 p-3 rounded">
                <ul class="mb-0 ps-3">
                    {''.join(f'<li>{p}</li>' for p in diag['summary_points'])}
                </ul>
            </div>
        </div>

        <!-- Baner Białej Listy IP -->
        {f'''<div class="alert alert-light border shadow-sm py-2 px-3 d-flex justify-content-between align-items-center mb-4">
            <div>
                <i class="fa-solid fa-shield-halved text-success me-2"></i>
                <strong>Aktywna Biała Lista IP (Wykluczone z analizy):</strong> <code class="text-dark bg-white border px-2 py-1 rounded">{", ".join(diag["whitelisted_entries"])}</code>
                <span class="ms-2 text-muted">| Wykluczono: <strong>{diag["whitelisted_requests"]:,}</strong> żądań z <strong>{diag["whitelisted_ips_count"]}</strong> zaufanych IP</span>
            </div>
            <span class="badge bg-success"><i class="fa-solid fa-check me-1"></i>Biała Lista Aktywna</span>
        </div>''' if diag.get('whitelisted_entries') else ''}

        <!-- Karty KPI -->
        <div class="row">
            <div class="col-md-2 col-sm-6">
                <div class="card kpi-card">
                    <div class="card-body">
                        <div class="kpi-label">Wszystkie Zapytania</div>
                        <div class="kpi-number text-primary">{self.processed_lines:,}</div>
                        <small class="text-muted">Statyczne: {self.static_requests:,}</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2 col-sm-6">
                <div class="card kpi-card">
                    <div class="card-body">
                        <div class="kpi-label">Pobrania Stron (HTML)</div>
                        <div class="kpi-number text-info">{self.page_requests:,}</div>
                        <small class="text-muted">Dynamiczne zasoby</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2 col-sm-6">
                <div class="card kpi-card warning">
                    <div class="card-body">
                        <div class="kpi-label">Unikalne Adresy IP</div>
                        <div class="kpi-number text-warning">{diag['unique_ips_total']:,}</div>
                        <small class="text-muted">Ponad progiem: {len(self.exceeded_ips)}</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2 col-sm-6">
                <div class="card kpi-card danger">
                    <div class="card-body">
                        <div class="kpi-label">Błędy HTTP 500</div>
                        <div class="kpi-number text-danger">{diag['err_500_count']:,}</div>
                        <small class="text-danger fw-bold">{diag['err_500_pct']}% wszystkich</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2 col-sm-6">
                <div class="card kpi-card danger">
                    <div class="card-body">
                        <div class="kpi-label">IP do Blacklisty</div>
                        <div class="kpi-number text-danger">{diag['blacklist_count']:,}</div>
                        <small class="text-muted">Wysokie zagrożenie</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2 col-sm-6">
                <div class="card kpi-card success">
                    <div class="card-body">
                        <div class="kpi-label">Próg URL (2x Mediana)</div>
                        <div class="kpi-number text-success">{self.url_threshold:.0f}</div>
                        <small class="text-muted">Mediana bazowa: {self.url_median:.1f}</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Sekcja Map Geograficznych -->
        <div class="row">
            <div class="col-lg-7">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fa-solid fa-earth-americas text-primary me-2"></i>Globalna Mapa Pochodzenia Ruchu (Kraje)</span>
                        <div>
                            <span class="badge bg-danger me-1"><i class="fa-solid fa-circle me-1" style="font-size:8px;"></i>Atak / Podejrzane &gt; 0</span>
                            <span class="badge bg-primary"><i class="fa-solid fa-circle me-1" style="font-size:8px;"></i>Ruch bez anomalii</span>
                        </div>
                    </div>
                    <div class="card-body p-2">
                        <div id="worldMap"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-5">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fa-solid fa-map-location-dot text-danger me-2"></i>Ruch w Polsce (Węzły Operatorów / Miasta)</span>
                        <div>
                            <span class="badge bg-danger me-1"><i class="fa-solid fa-circle me-1" style="font-size:8px;"></i>Atak / Podejrzane &gt; 0</span>
                            <span class="badge bg-primary"><i class="fa-solid fa-circle me-1" style="font-size:8px;"></i>Ruch bez anomalii</span>
                        </div>
                    </div>
                    <div class="card-body p-2">
                        <div id="polandMap"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Sekcja Wykresów Analitycznych -->
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                        <span><i class="fa-solid fa-chart-line text-primary me-2"></i>Rozkład Ruchu w Czasie (Oś Godzinowa)</span>
                        <div class="btn-group btn-group-sm" role="group" aria-label="Nawigacja osią czasu">
                            <button type="button" class="btn btn-outline-secondary" onclick="window.timelineChart &amp;&amp; window.timelineChart.pan({{x: 80}})" title="Przesuń w lewo (wcześniejszy czas)">
                                <i class="fa-solid fa-arrow-left me-1"></i>W lewo
                            </button>
                            <button type="button" class="btn btn-outline-secondary" onclick="window.timelineChart &amp;&amp; window.timelineChart.pan({{x: -80}})" title="Przesuń w prawo (późniejszy czas)">
                                W prawo<i class="fa-solid fa-arrow-right ms-1"></i>
                            </button>
                            <button type="button" class="btn btn-outline-primary" onclick="window.timelineChart &amp;&amp; window.timelineChart.zoom(1.3)" title="Przybliż (Zoom In)">
                                <i class="fa-solid fa-magnifying-glass-plus me-1"></i>Przybliż
                            </button>
                            <button type="button" class="btn btn-outline-primary" onclick="window.timelineChart &amp;&amp; window.timelineChart.zoom(0.75)" title="Oddal (Zoom Out)">
                                <i class="fa-solid fa-magnifying-glass-minus me-1"></i>Oddal
                            </button>
                            <button type="button" class="btn btn-outline-danger" onclick="window.timelineChart &amp;&amp; window.timelineChart.resetZoom()" title="Przywróć pełny zakres osi czasu">
                                <i class="fa-solid fa-rotate-left me-1"></i>Reset
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-2 px-1">
                            <small class="text-muted">
                                <i class="fa-solid fa-circle-info text-primary me-1"></i>
                                <strong>Nawigacja:</strong> Użyj <strong>kółka myszy</strong> lub gestu, aby przybliżać, oraz <strong>przeciągaj myszką</strong>, aby przesuwać wykres na osi czasu.
                            </small>
                        </div>
                        <div class="chart-container-timeline">
                            <canvas id="timelineChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-header"><i class="fa-solid fa-chart-pie text-success me-2"></i>Klasyfikacja Ruchu</div>
                    <div class="card-body">
                        <div class="chart-container-pie">
                            <canvas id="trafficTypeChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-header"><i class="fa-solid fa-server text-warning me-2"></i>Kody Odpowiedzi HTTP</div>
                    <div class="card-body">
                        <div class="chart-container-pie">
                            <canvas id="statusChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header"><i class="fa-solid fa-flag text-info me-2"></i>Główne Kraje Pochodzenia</div>
                    <div class="card-body">
                        <div class="chart-container-bar">
                            <canvas id="countriesChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header"><i class="fa-solid fa-network-wired text-purple me-2"></i>Główni Operatorzy i Sieci (ASN / ISP)</div>
                    <div class="card-body">
                        <div class="chart-container-bar">
                            <canvas id="asnChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabela: Top URL-e przekraczające próg -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fa-solid fa-link text-primary me-2"></i>Najczęściej Odpytywane Adresy URL i Strony (Powyżej Progu: {self.url_threshold:.0f} żądań)</span>
                <span class="badge bg-primary">Znaleziono: {len(self.exceeded_urls)}</span>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table id="urlTable" class="table table-hover table-striped align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>Adres URL / Strona</th>
                                <th>Sekcja Serwisu</th>
                                <th>Liczba Żądań</th>
                                <th>Unikalne IP</th>
                                <th>Błędy 500</th>
                                <th>Błędy 403</th>
                                <th>Status Progu</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(f"""<tr>
                                <td><code class="text-dark fw-bold">{clean_string(u['url'])}</code></td>
                                <td><span class="badge bg-secondary">{clean_string(u['section'])}</span></td>
                                <td><strong>{u['count']:,}</strong></td>
                                <td>{u['unique_ips']:,}</td>
                                <td><span class="badge {'bg-danger' if u['status_500'] > 0 else 'bg-light text-dark'}">{u['status_500']:,}</span></td>
                                <td><span class="badge {'bg-warning text-dark' if u['status_403'] > 0 else 'bg-light text-dark'}">{u['status_403']:,}</span></td>
                                <td><span class="badge bg-danger">Przekroczony ({u['count']/self.url_median:.1f}x mediana)</span></td>
                            </tr>""" for u in self.exceeded_urls[:100])}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Tabela: Adresy IP z Blacklisty / Wykryte Ataki -->
        <div class="card border-danger mb-4 shadow-sm">
            <div class="card-header bg-danger text-white d-flex justify-content-between align-items-center">
                <span><i class="fa-solid fa-shield-virus me-2"></i>Zidentyfikowane Złośliwe Adresy IP do Zablokowania (Blacklist - Threat Score &ge; 50% lub Złośliwy Bot)</span>
                <span class="badge bg-light text-danger fw-bold">{len(self.ips_to_blacklist)} IP do natychmiastowej blokady</span>
            </div>
            <div class="card-body">
                <p class="text-muted small mb-3">Poniższe adresy IP przekroczyły próg anomalnego ruchu i zostały zakwalifikowane jako złośliwe boty, skanery lub narzędzia automatyzacji generujące błędy serwera. Zostały one automatycznie wyeksportowane do pliku <code>blacklist_ips.txt</code> oraz reguł blokujących Apache.</p>
                <div class="table-responsive">
                    <table id="blacklistTable" class="table table-hover table-striped align-middle">
                        <thead class="table-dark">
                            <tr>
                                <th>Adres IP</th>
                                <th>Kraj</th>
                                <th>Operator / ASN</th>
                                <th>Klasyfikacja</th>
                                <th>Żądania Stron</th>
                                <th>Statyczne</th>
                                <th>Błędy (500/403)</th>
                                <th>Threat Score &amp; Powody</th>
                                <th>Przykładowy User-Agent</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(f"""<tr>
                                <td><strong class="text-danger">{ip_item['ip']}</strong></td>
                                <td><span class="fi fi-{ip_item['country_code'].lower()}"></span> {clean_string(ip_item['country_name'])} ({ip_item['country_code']})</td>
                                <td><small class="fw-semibold">{clean_string(ip_item['isp'])}</small><br><span class="badge bg-light text-dark">{ip_item['asn']}</span></td>
                                <td><span class="badge {ip_item['badge_class']}">{clean_string(ip_item['ua_label'])}</span></td>
                                <td><strong>{ip_item['page_requests']:,}</strong></td>
                                <td>{ip_item['static_requests']:,}</td>
                                <td><span class="badge {'bg-danger' if ip_item['status_500'] > 0 else 'bg-warning text-dark'}">{ip_item['status_500'] + ip_item['status_403']} ({ip_item['error_rate']}%)</span></td>
                                <td>
                                    <div class="progress mb-1" style="height: 16px;">
                                        <div class="progress-bar bg-danger" style="width: {ip_item['threat_score']}%;">
                                            {ip_item['threat_score']}%
                                        </div>
                                    </div>
                                    <small class="text-muted d-block" style="font-size: 0.75rem;">{clean_string('; '.join(ip_item['threat_reasons']))}</small>
                                </td>
                                <td><small class="text-muted" title="{clean_string(ip_item['top_ua'])}">{clean_string(ip_item['top_ua'][:40])}...</small></td>
                            </tr>""" for ip_item in self.exceeded_ips if ip_item['ip'] in self.ips_to_blacklist)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Tabela: Top IP i ich charakterystyka -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fa-solid fa-users-rays text-primary me-2"></i>Wszystkie Zidentyfikowane Adresy IP Ponad Progiem Ruchu (Próg: {self.ip_threshold:.0f} żądań)</span>
                <span class="badge bg-primary">Łącznie: {len(self.exceeded_ips)} IP</span>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table id="ipTable" class="table table-hover table-striped align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>Adres IP</th>
                                <th>Kraj</th>
                                <th>Operator / ASN</th>
                                <th>Klasyfikacja / Bot</th>
                                <th>Żądania Stron</th>
                                <th>Statyczne</th>
                                <th>Błędy (500/403)</th>
                                <th>Threat Score</th>
                                <th>Przykładowy User-Agent</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(f"""<tr>
                                <td><strong class="{'text-danger' if ip_item['ip'] in self.ips_to_blacklist else 'text-primary'}">{ip_item['ip']}</strong></td>
                                <td><span class="fi fi-{ip_item['country_code'].lower()}"></span> {clean_string(ip_item['country_name'])} ({ip_item['country_code']})</td>
                                <td><small class="fw-semibold">{clean_string(ip_item['isp'])}</small><br><span class="badge bg-light text-dark">{ip_item['asn']}</span></td>
                                <td><span class="badge {ip_item['badge_class']}">{clean_string(ip_item['ua_label'])}</span></td>
                                <td><strong>{ip_item['page_requests']:,}</strong></td>
                                <td>{ip_item['static_requests']:,}</td>
                                <td><span class="badge {'bg-danger' if ip_item['status_500'] > 0 else 'bg-light text-dark'}">{ip_item['status_500'] + ip_item['status_403']} ({ip_item['error_rate']}%)</span></td>
                                <td>
                                    <div class="progress" style="height: 16px;">
                                        <div class="progress-bar {'bg-danger' if ip_item['threat_score']>=50 else ('bg-warning' if ip_item['threat_score']>=30 else 'bg-success')}" style="width: {ip_item['threat_score']}%;">
                                            {ip_item['threat_score']}%
                                        </div>
                                    </div>
                                </td>
                                <td><small class="text-muted" title="{clean_string(ip_item['top_ua'])}">{clean_string(ip_item['top_ua'][:40])}...</small></td>
                            </tr>""" for ip_item in self.exceeded_ips)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Sekcja Reguł Blokowania: Apache & Blacklist -->
        <div class="row">
            <div class="col-md-6">
                <div class="card position-relative">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fa-brands fa-redhat text-danger me-2"></i>Reguły Blokowania dla Apache (.htaccess / httpd.conf)</span>
                        <button class="btn btn-sm btn-outline-primary" onclick="copyToClipboard('apacheRules')"><i class="fa-regular fa-copy me-1"></i>Kopiuj</button>
                    </div>
                    <div class="card-body">
                        <p class="small text-muted mb-2">Poniższe reguły blokują zidentyfikowane złośliwe boty oraz podejrzane adresy IP:</p>
                        <pre id="apacheRules" class="code-block"># --- Blokada Złośliwych Botów i Scraperów ---
&lt;IfModule mod_setenvif.c&gt;
{''.join(f'    SetEnvIfNoCase User-Agent "{bot}" bad_bot=1\\n' for bot in self.suspected_bots_to_block)}
    SetEnvIfNoCase User-Agent "^$" bad_bot=1
&lt;/IfModule&gt;

&lt;RequireAll&gt;
    Require all granted
    Require not env bad_bot
{''.join(f'    Require not ip {ip}\\n' for ip in sorted(self.ips_to_blacklist)[:100])}
&lt;/RequireAll&gt;</pre>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card position-relative">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fa-solid fa-ban text-danger me-2"></i>Lista IP do Blacklisty (Zewnętrzny plik / Firewall)</span>
                        <a href="blacklist_ips.txt" download class="btn btn-sm btn-outline-danger"><i class="fa-solid fa-download me-1"></i>Pobierz TXT ({len(self.ips_to_blacklist)} IP)</a>
                    </div>
                    <div class="card-body">
                        <p class="small text-muted mb-2">Gotowe polecenia iptables do szybkiego odcięcia ruchu atakującego na poziomie jądra systemu:</p>
                        <pre id="iptablesRules" class="code-block"># Polecenia Linux iptables:
{''.join(f'iptables -A INPUT -s {ip} -j DROP\\n' for ip in sorted(self.ips_to_blacklist)[:50])}
# ... pobierz pełny plik blacklist_ips.txt dla wszystkich {len(self.ips_to_blacklist)} adresów</pre>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <!-- Skrypty JS: Leaflet, Chart.js, Hammer.js, Chart.js Zoom Plugin, jQuery, DataTables -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/js/bootstrap.bundle.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/hammer.js/2.0.8/hammer.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chartjs-plugin-zoom/2.0.1/chartjs-plugin-zoom.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/datatables.net/1.13.6/jquery.dataTables.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/datatables.net-bs5/1.13.6/dataTables.bootstrap5.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>

    <script>
        // Tłumaczenia DataTables dla języka polskiego (inline, bez zewnętrznych zapytań AJAX)
        const dtPlTranslation = {{
            processing: "Przetwarzanie...",
            search: "Szukaj:",
            lengthMenu: "Pokaż _MENU_ pozycji",
            info: "Pozycje od _START_ do _END_ z _TOTAL_ łącznie",
            infoEmpty: "Pozycji 0 z 0 dostępnych",
            infoFiltered: "(odfiltrowano z _MAX_ wszystkich pozycji)",
            loadingRecords: "Wczytywanie...",
            zeroRecords: "Nie znaleziono pasujących pozycji",
            emptyTable: "Brak danych w tabeli",
            paginate: {{
                first: "Pierwsza",
                previous: "Poprzednia",
                next: "Następna",
                last: "Ostatnia"
            }},
            aria: {{
                sortAscending: ": aktywuj, by posortować kolumnę rosnąco",
                sortDescending: ": aktywuj, by posortować kolumnę malejąco"
            }}
        }};

        // Inicjalizacja DataTables
        $(document).ready(function() {{
            if ($('#blacklistTable').length) {{
                $('#blacklistTable').DataTable({{
                    pageLength: 10,
                    order: [[6, 'desc']], // sortowanie po Threat Score / błędach
                    language: dtPlTranslation
                }});
            }}
            $('#urlTable').DataTable({{
                pageLength: 10,
                order: [[2, 'desc']],
                language: dtPlTranslation
            }});
            $('#ipTable').DataTable({{
                pageLength: 10,
                order: [[4, 'desc']],
                language: dtPlTranslation
            }});
        }});

        // Funkcja kopiowania do schowka
        function copyToClipboard(elementId) {{
            const text = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(text).then(() => {{
                alert('Skopiowano reguły do schowka!');
            }});
        }}

        // --- KONFIGURACJA KAFELKÓW MAPY (CartoDB Voyager / OpenStreetMap) ---
        // CartoDB Voyager nie blokuje zapytań z refererów lokalnych / file:// w przeciwieństwie do publicznego serwera OSM tile
        const tileLayerUrl = 'https://{{s}}.basemaps.cartocdn.com/rastertiles/voyager/{{z}}/{{x}}/{{y}}{{r}}.png?key=cb1_4t79_1_629c109cfb4f4bd4526a5bb3';
        const tileLayerOptions = {{
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions" target="_blank" rel="noreferrer">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        }};

        // --- MAPA ŚWIATA (LEAFLET) ---
        const worldMap = L.map('worldMap').setView([30, 10], 2);
        L.tileLayer(tileLayerUrl, tileLayerOptions).addTo(worldMap);

        const worldData = {json.dumps(map_countries_data)};
        worldData.forEach(c => {{
            if (c.lat !== 0 && c.lng !== 0) {{
                const radius = Math.max(6, Math.min(35, Math.sqrt(c.requests) * 0.8));
                const isAttack = (c.attack_requests || 0) > 0;
                const color = isAttack ? '#ef4444' : '#3b82f6';
                const circle = L.circleMarker([c.lat, c.lng], {{
                    radius: radius,
                    fillColor: color,
                    color: '#ffffff',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.75
                }}).addTo(worldMap);

                circle.bindPopup(`
                    <div style="font-family: 'Inter', sans-serif;">
                        <h6 style="margin:0 0 6px 0; font-weight:700;">${{c.name}} (${{c.code}})</h6>
                        <div>Żądania stron: <strong>${{c.requests.toLocaleString()}}</strong></div>
                        <div>Atak/Podejrzane: <strong style="color:${{color}};">${{c.attack_requests.toLocaleString()}}</strong></div>
                    </div>
                `);
            }}
        }});

        // --- MAPA POLSKI (LEAFLET) ---
        const polandMap = L.map('polandMap').setView([52.1, 19.4], 6);
        L.tileLayer(tileLayerUrl, tileLayerOptions).addTo(polandMap);

        const plData = {json.dumps(map_pl_cities_data)};
        plData.forEach(city => {{
            const radius = Math.max(8, Math.min(40, Math.sqrt(city.requests) * 0.9));
            const isAttack = (city.attack_requests || 0) > 0;
            const color = isAttack ? '#ef4444' : '#3b82f6';
            const circle = L.circleMarker([city.lat, city.lng], {{
                radius: radius,
                fillColor: color,
                color: '#ffffff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.75
            }}).addTo(polandMap);

            circle.bindPopup(`
                <div style="font-family: 'Inter', sans-serif;">
                    <h6 style="margin:0 0 6px 0; font-weight:700;">Węzeł: ${{city.city}}</h6>
                    <div>Wolumen ruchu: <strong>${{city.requests.toLocaleString()}}</strong> żądań</div>
                    <div>Atak/Podejrzane: <strong style="color:${{color}};">${{city.attack_requests.toLocaleString()}}</strong></div>
                </div>
            `);
        }});

        // --- WYKRESY CHART.JS ---
        // 1. Timeline (z obsługą przybliżania i przesuwania osi czasu Zoom & Pan)
        window.timelineChart = new Chart(document.getElementById('timelineChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(chart_timeline_labels)},
                datasets: [{{
                    label: 'Liczba żądań / godzina',
                    data: {json.dumps(chart_timeline_values)},
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }},
                    tooltip: {{
                        mode: 'index',
                        intersect: false
                    }},
                    zoom: {{
                        pan: {{
                            enabled: true,
                            mode: 'x',
                            threshold: 5
                        }},
                        zoom: {{
                            wheel: {{
                                enabled: true,
                                speed: 0.1
                            }},
                            pinch: {{
                                enabled: true
                            }},
                            mode: 'x'
                        }}
                    }}
                }},
                interaction: {{
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }},
                scales: {{
                    x: {{
                        grid: {{ display: true, color: 'rgba(0,0,0,0.05)' }}
                    }},
                    y: {{
                        beginAtZero: true,
                        grid: {{ display: true, color: 'rgba(0,0,0,0.05)' }}
                    }}
                }}
            }}
        }});

        // 2. Traffic Type Pie
        new Chart(document.getElementById('trafficTypeChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(chart_type_labels)},
                datasets: [{{
                    data: {json.dumps(chart_type_values)},
                    backgroundColor: ['#ef4444', '#3b82f6', '#f59e0b', '#10b981']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12 }} }} }}
            }}
        }});

        // 3. Status Codes Pie
        new Chart(document.getElementById('statusChart'), {{
            type: 'pie',
            data: {{
                labels: {json.dumps(chart_status_labels)},
                datasets: [{{
                    data: {json.dumps(chart_status_values)},
                    backgroundColor: ['#10b981', '#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#64748b']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12 }} }} }}
            }}
        }});

        // 4. Top Countries Bar
        new Chart(document.getElementById('countriesChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(chart_countries_labels)},
                datasets: [{{
                    label: 'Żądania',
                    data: {json.dumps(chart_countries_values)},
                    backgroundColor: '#0284c7'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true }} }}
            }}
        }});

        // 5. Top ASN Bar
        new Chart(document.getElementById('asnChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(chart_asn_labels)},
                datasets: [{{
                    label: 'Żądania',
                    data: {json.dumps(chart_asn_values)},
                    backgroundColor: '#8b5cf6'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true }} }}
            }}
        }});
    </script>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"📊 Wygenerowano interaktywny raport HTML: {output_path}")

# ==============================================================================
# CLI & PUNKT WEJŚCIA
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Web Traffic Analyzer & DDoS / Bot Detector - Analiza logów Apache pod kątem anomalii i ataków (dostosowana do systemów Linux i Windows)."
    )
    parser.add_argument(
        '-p', '--path', default='/var/log/httpd',
        help="Ścieżka do katalogu z logami serwera lub pojedynczego pliku (domyślnie: /var/log/httpd)"
    )
    parser.add_argument(
        '-m', '--mask', default='smartsite.mazovia.app-access.log*',
        help="Maska nazw plików logów we wskazanym katalogu (domyślnie: smartsite.mazovia.app-access.log*, np. '*access*.log*' lub 'access_log*')"
    )
    parser.add_argument(
        '-l', '--log', default=None,
        help="Opcjonalny bezpośredni wzorzec pliku (np. 'logs/*.log', dla zachowania wstecznej kompatybilności)"
    )
    parser.add_argument(
        '-o', '--output', '--output-html', dest='output', default='traffic_analysis_report.html',
        help="Ścieżka do wyjściowego raportu HTML lub katalog docelowy na raporty (domyślnie: traffic_analysis_report.html w bieżącym katalogu)"
    )
    parser.add_argument(
        '-b', '--output-blacklist', default='blacklist_ips.txt',
        help="Ścieżka lub nazwa pliku wyjściowego z blacklistą IP (domyślnie: blacklist_ips.txt)"
    )
    parser.add_argument(
        '--output-apache-rules', default='apache_block_rules.conf',
        help="Ścieżka lub nazwa pliku z regułami Apache (domyślnie: apache_block_rules.conf)"
    )
    parser.add_argument(
        '-d', '--date', default=None,
        help="Filtruj wpisy po dacie w formacie DD/Mon/YYYY (np. 23/Oct/2026) lub 'all' (domyślnie: wszystkie)"
    )
    parser.add_argument(
        '--cache-file', default='.traffic_analyzer_cache.json',
        help="Ścieżka do pliku pamięci podręcznej (domyślnie: .traffic_analyzer_cache.json)"
    )
    parser.add_argument(
        '--no-cache', action='store_true',
        help="Wyłącza odczyt i zapis pamięci podręcznej (wymusza pełne parsowanie wszystkich plików)"
    )
    parser.add_argument(
        '--clear-cache', action='store_true',
        help="Czyści istniejącą pamięć podręczną przed rozpoczęciem analizy"
    )
    parser.add_argument(
        '--country-db', default='GeoLite2-Country.mmdb',
        help="Ścieżka do bazy MaxMind GeoLite2-Country.mmdb"
    )
    parser.add_argument(
        '--asn-db', default='GeoLite2-ASN.mmdb',
        help="Ścieżka do bazy MaxMind GeoLite2-ASN.mmdb"
    )
    parser.add_argument(
        '--url-threshold-mult', type=float, default=2.0,
        help="Mnożnik mediany dla progu URL (domyślnie: 2.0)"
    )
    parser.add_argument(
        '--ip-threshold-mult', type=float, default=2.0,
        help="Mnożnik mediany dla progu IP (domyślnie: 2.0)"
    )
    parser.add_argument(
        '--min-url-threshold', type=float, default=20.0,
        help="Minimalny próg żądań dla URL (domyślnie: 20)"
    )
    parser.add_argument(
        '--min-ip-threshold', type=float, default=20.0,
        help="Minimalny próg żądań dla IP (domyślnie: 20)"
    )
    parser.add_argument(
        '-w', '--whitelist', default=None,
        help="Dodatkowe adresy IP / podsieci CIDR do białej listy (oddzielone przecinkami, np. '1.2.3.4,10.0.0.0/8')"
    )
    parser.add_argument(
        '--whitelist-file', default=None,
        help="Ścieżka do pliku z białą listą adresów IP/podsieci (jeden wpis na linię)"
    )
    parser.add_argument(
        '--max-lines', type=int, default=None,
        help="Opcjonalny limit przetwarzanych linii (do szybkich testów)"
    )

    args = parser.parse_args()

    extra_whitelist = []
    if args.whitelist:
        extra_whitelist.extend([x.strip() for x in args.whitelist.split(',') if x.strip()])
    if args.whitelist_file and os.path.exists(args.whitelist_file):
        with open(args.whitelist_file, 'r', encoding='utf-8') as wf:
            for line in wf:
                line = line.strip()
                if line and not line.startswith('#'):
                    extra_whitelist.append(line)

    # Rozwiązanie ścieżek wyjściowych (plik raportu, blacklist, reguły apache)
    output_target = args.output
    if os.path.isdir(output_target) or output_target.endswith('/') or output_target.endswith('\\'):
        out_dir = output_target.rstrip('/\\')
        os.makedirs(out_dir, exist_ok=True)
        html_out = os.path.join(out_dir, 'traffic_analysis_report.html')
        blacklist_out = os.path.join(out_dir, os.path.basename(args.output_blacklist))
        apache_out = os.path.join(out_dir, os.path.basename(args.output_apache_rules))
    else:
        html_out = output_target
        out_dir = os.path.dirname(html_out) or '.'
        if out_dir != '.' and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        blacklist_out = os.path.join(out_dir, os.path.basename(args.output_blacklist)) if out_dir != '.' and not os.path.isabs(args.output_blacklist) else args.output_blacklist
        apache_out = os.path.join(out_dir, os.path.basename(args.output_apache_rules)) if out_dir != '.' and not os.path.isabs(args.output_apache_rules) else args.output_apache_rules

    analyzer = WebTrafficAnalyzer(
        log_path=args.path,
        log_mask=args.mask,
        log_pattern=args.log,
        country_db=args.country_db,
        asn_db=args.asn_db,
        url_threshold_mult=args.url_threshold_mult,
        ip_threshold_mult=args.ip_threshold_mult,
        min_url_threshold=args.min_url_threshold,
        min_ip_threshold=args.min_ip_threshold,
        filter_date=args.date,
        max_lines=args.max_lines,
        whitelist=extra_whitelist if extra_whitelist else None,
        cache_file=args.cache_file,
        use_cache=(not args.no_cache),
        clear_cache=args.clear_cache
    )

    success = analyzer.run_analysis()
    if success:
        analyzer.generate_blacklist_file(blacklist_out)
        analyzer.generate_apache_rules_file(apache_out)
        analyzer.generate_html_report(html_out)
        
        print("\n" + "="*70)
        print("🎉 ANALIZA ZAKOŃCZONA SUKCESEM!")
        print(f"📊 Werdykt: {analyzer.diagnosis['verdict']}")
        print(f"📄 Raport HTML:       {os.path.abspath(html_out)}")
        print(f"🚫 Blacklista IP:      {os.path.abspath(blacklist_out)}")
        print(f"🛡️  Reguły Apache:     {os.path.abspath(apache_out)}")
        print("="*70)

if __name__ == '__main__':
    main()
