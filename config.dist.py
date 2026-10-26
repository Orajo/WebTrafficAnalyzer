#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dystrybucyjny (wzorcowy) plik konfiguracyjny Web Traffic Analyzer & DDoS / Bot Detector.

Skopiuj ten plik jako `config.py` i dostosuj wartości (zwłaszcza białą listę IP
oraz domyślną maskę/ścieżkę logów) do konkretnego środowiska / klienta:

    cp config.dist.py config.py     (Linux)
    Copy-Item config.dist.py config.py   (Windows / PowerShell)

Plik `config.py` nie powinien być nadpisywany automatycznie przy aktualizacji
narzędzia - wszystkie ustawienia specyficzne dla danego wdrożenia powinny trafiać
właśnie tam, natomiast ten plik (`config.dist.py`) służy jedynie jako wzorzec
i punkt odniesienia dla domyślnych wartości.
"""

# ==============================================================================
# BIAŁA LISTA IP / PODSIECI WYKLUCZONYCH Z ANALIZY
# ==============================================================================

# Biała lista adresów IP i podsieci (CIDR) wykluczonych z analizy
# (np. własne datacenter, serwery aplikacyjne, dedykowane systemy monitoringu).
# Przykład: '217.153.27.58',  # Nasze datacenter
DEFAULT_WHITELIST_IPS = [
]

# ==============================================================================
# ZASOBY STATYCZNE
# ==============================================================================

STATIC_EXTENSIONS = (
    '.css', '.js', '.mjs', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
    '.ico', '.bmp', '.tiff', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.map', '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.swf'
)

# ==============================================================================
# SŁOWNIKI KLASYFIKACJI USER-AGENT
# ==============================================================================

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

# Klucze narzędzi traktowanych jako monitoring (nie generują wpisu do blacklisty)
MONITORING_TOOL_KEYS = ('zabbix', 'prometheus')

# Ogólne wzorce wykrywania nieznanych botów po słowach kluczowych w User-Agent
GENERIC_BOT_KEYWORDS = ('bot', 'spider', 'crawler', 'scraper', 'checker', 'scan', 'probe')

# Wagi punktowe (threat_weight) przypisywane w zależności od kategorii User-Agent
UA_WEIGHT_EMPTY = 80
UA_WEIGHT_SEARCH_BOT = 0
UA_WEIGHT_SEO_AI_BOT = 25
UA_WEIGHT_MONITORING = 10
UA_WEIGHT_SUSPICIOUS_TOOL = 90
UA_WEIGHT_GENERIC_BOT = 40
UA_WEIGHT_HUMAN = 0

# ==============================================================================
# WSPÓŁRZĘDNE GEOGRAFICZNE DO MAP LEAFLET
# ==============================================================================

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

# ==============================================================================
# DOMYŚLNE WARTOŚCI PARAMETRÓW CLI
# ==============================================================================

DEFAULT_LOG_PATH = '/var/log/httpd'
DEFAULT_LOG_MASK = 'access_log*'
DEFAULT_LOG_PATTERN = None
DEFAULT_OUTPUT_HTML = 'traffic_analysis_report.html'
DEFAULT_OUTPUT_BLACKLIST = 'blacklist_ips.txt'
DEFAULT_OUTPUT_APACHE_RULES = 'apache_block_rules.conf'
DEFAULT_CACHE_FILE = '.traffic_analyzer_cache.json'
DEFAULT_COUNTRY_DB = 'GeoLite2-Country.mmdb'
DEFAULT_ASN_DB = 'GeoLite2-ASN.mmdb'
DEFAULT_FILTER_DATE = None
DEFAULT_MAX_LINES = None

# ==============================================================================
# PROGI STATYSTYCZNE WYKRYWANIA ANOMALII (REGUŁA 2 x MEDIANA)
# ==============================================================================

DEFAULT_URL_THRESHOLD_MULT = 2.0    # Mnożnik mediany dla progu URL
DEFAULT_IP_THRESHOLD_MULT = 2.0     # Mnożnik mediany dla progu IP
DEFAULT_MIN_URL_THRESHOLD = 20.0    # Minimalny bezwzględny próg żądań dla URL
DEFAULT_MIN_IP_THRESHOLD = 20.0     # Minimalny bezwzględny próg żądań dla IP
# Próg dla sekcji serwisu wyliczany jest jako max(mediana * mnożnik, MIN_URL_THRESHOLD * SECTION_MIN_THRESHOLD_MULT)
SECTION_MIN_THRESHOLD_MULT = 2.0

# ==============================================================================
# SILNIK OCENY ZAGROŻEŃ (THREAT SCORE 0-100%)
# ==============================================================================

# Wagi punktowe poszczególnych czynników ryzyka
THREAT_WEIGHT_MALICIOUS_UA = 45        # Podejrzany / złośliwy User-Agent
THREAT_WEIGHT_AUTOMATION_TOOL = 25     # Narzędzie automatyzacji / skrypt (nie-crawler)
THREAT_WEIGHT_NO_STATIC_ASSETS = 25    # Brak pobierania zasobów statycznych (CSS/JS/grafiki)
THREAT_WEIGHT_HIGH_ERROR_RATE = 20     # Wysoki odsetek błędów serwera (500/403/429)
THREAT_WEIGHT_CLOUD_DATACENTER = 20    # Ruch z centrum danych / chmury obliczeniowej

# Progi warunkujące naliczenie poszczególnych wag
MIN_PAGE_REQUESTS_FOR_STATIC_CHECK = 50   # Minimalna liczba żądań stron do oceny wskaźnika zasobów statycznych
STATIC_ASSET_RATIO_THRESHOLD = 0.05       # Próg wskaźnika pobierania zasobów statycznych (5%)
HIGH_ERROR_RATE_PERCENT_THRESHOLD = 15    # Próg odsetka błędów serwera (15%)

# Próg kwalifikacji IP do blacklisty / klasyfikacji jako ATTACKER
BLACKLIST_THREAT_SCORE_THRESHOLD = 50
# Próg oznaczenia ruchu jako "podejrzanie intensywny użytkownik" (SUSPICIOUS_HEAVY_USER)
SUSPICIOUS_HEAVY_USER_THREAT_SCORE_THRESHOLD = 30

# Słowa kluczowe identyfikujące dostawców chmur / centrów danych w nazwie organizacji ASN
CLOUD_DATACENTER_KEYWORDS = (
    'amazon', 'aws', 'google-cloud', 'digitalocean', 'hetzner', 'ovh',
    'linode', 'alibaba', 'tencent', 'microsoft-corp', 'm247', 'host',
    'datacenter', 'vultr'
)

# ==============================================================================
# PROGI DIAGNOSTYCZNE WERDYKTU GLOBALNEGO
# ==============================================================================

VERDICT_ATTACK_REQUEST_RATIO = 0.25     # Udział żądań od ATTACKER w ruchu stron, powyżej którego diagnozowany jest atak
VERDICT_ERROR_500_PCT_THRESHOLD = 3.0   # Udział procentowy błędów HTTP 500 w całym ruchu, powyżej którego diagnozowany jest atak
VERDICT_BLACKLIST_COUNT_THRESHOLD = 5   # Liczba zablokowanych IP, powyżej której diagnozowany jest atak
VERDICT_CRAWLER_REQUEST_RATIO = 0.40    # Udział żądań od wyszukiwarek, powyżej którego diagnozowane jest intensywne indeksowanie

# ==============================================================================
# LIMITY GENEROWANYCH RAPORTÓW I REGUŁ
# ==============================================================================

REPORT_URL_TABLE_LIMIT = 100           # Maksymalna liczba wierszy w tabeli najbardziej obciążonych URL
REPORT_APACHE_IP_RULES_LIMIT = 100     # Maksymalna liczba reguł "Require not ip" w podpowiedzi raportu HTML
REPORT_IPTABLES_RULES_LIMIT = 50       # Maksymalna liczba reguł iptables w podpowiedzi raportu HTML
APACHE_RULES_FILE_IP_LIMIT = 500       # Maksymalna liczba reguł "Require not ip" w pliku apache_block_rules.conf

# ==============================================================================
# KONFIGURACJA MAPY (LEAFLET / OPENSTREETMAP)
# ==============================================================================

# Domyślnie darmowe kafelki OpenStreetMap. Jeśli raport jest otwierany lokalnie
# (file://) lub bez poprawnego nagłówka Referer, rozważ użycie alternatywnego
# dostawcy kafelków (np. własny klucz CartoDB / MapTiler), aby uniknąć błędów
# "403 Access Blocked".
MAP_TILE_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png'
MAP_TILE_ATTRIBUTION = (
    '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer">OpenStreetMap</a> contributors'
)
MAP_TILE_SUBDOMAINS = 'abc'
