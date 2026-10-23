# Web Traffic Analyzer & DDoS / Bot Detector

Zaawansowane, wysokowydajne narzędzie w języku Python do automatycznej analizy logów serwerów WWW (Apache / HTTPD / Nginx), stworzone z myślą o wykrywaniu ataków DDoS, anomalii ruchu, botnetów, złośliwych skanerów oraz agresywnego scrapingu (AI/SEO).

Program generuje interaktywne raporty HTML z mapami geograficznymi (OpenStreetMap / Leaflet), dynamicznymi wykresami z obsługą przybliżania osi czasu (Chart.js + Pan/Zoom) oraz gotowymi regułami blokującymi dla serwera Apache i firewalla systemowego (`iptables` / `ipset` / `fail2ban`).

---

## Spis treści
- [Główne Możliwości](#główne-możliwości)
- [Wymagania i Instalacja](#wymagania-i-instalacja)
- [Szybki Start](#szybki-start)
- [Parametry Wiersza Poleceń (CLI)](#parametry-wiersza-poleceń-cli)
- [Przykłady Użycia](#przykłady-użycia)
- [Zastosowane Algorytmy i Metodologia](#zastosowane-algorytmy-i-metodologia)
  - [1. Normalizacja i Filtrowanie Zasobów Statycznych](#1-normalizacja-i-filtrowanie-zasobów-statycznych)
  - [2. Dynamiczne Progi Ruchu (Reguła 2 × Mediana)](#2-dynamiczne-progi-ruchu-reguła-2--mediana)
  - [3. Klasyfikacja Behawioralna i Sygnaturowa (User-Agent)](#3-klasyfikacja-behawioralna-i-sygnaturowa-user-agent)
  - [4. Algorytm Scoringu Zagrożeń (Threat Score 0–100%)](#4-algorytm-scoringu-zagrożeń-threat-score-0100)
  - [5. Zautomatyzowana Diagnoza i Werdykt Globalny](#5-zautomatyzowana-diagnoza-i-werdykt-globalny)
  - [6. Mechanizm Pracy na Żywym Serwerze i Pamięć Podręczna (Cache)](#6-mechanizm-pracy-na-żywym-serwerze-i-pamięć-podręczna-cache)
- [Generowane Pliki i Raporty](#generowane-pliki-i-raporty)
- [Licencja i Bezpieczeństwo](#licencja-i-bezpieczeństwo)

---

## Główne Możliwości

- **Analiza Skupiona na Treści:** Automatyczne oddzielenie zapytań o strony dynamiczne/HTML od zasobów statycznych (obrazki, CSS, JS, fonty, multimedia), co zapobiega zniekształcaniu statystyk ruchu.
- **Dynamiczne Wykrywanie Anomalii:** Wyznaczanie progów nadmiernego obciążenia w oparciu o statystykę odporną na wartości odstające ($2 \times \text{mediana}$).
- **Geolokalizacja Offline:** Integracja z bazami MaxMind GeoLite2 (`GeoLite2-Country.mmdb` oraz `GeoLite2-ASN.mmdb`) bez konieczności odpytywania zewnętrznych API.
- **Zaawansowany Threat Scoring:** Wieloczynnikowa ocena ryzyka dla każdego podejrzanego adresu IP (0–100%) uwzględniająca błędy serwera (500/403/429), profil pobierania zasobów, rodzaj hostingu/chmury oraz sygnatury klientów.
- **Gotowe Reguły Ochronne:** Automatyczny eksport listy złośliwych adresów IP do pliku tekstowego oraz reguł blokujących Apache (`Require not ip ...` i blokady `BrowserMatchNoCase`).
- **Interaktywny Raport HTML:** 
  - Mapa świata oraz szczegółowa mapa miast w Polsce (Leaflet + kafelki CartoDB Voyager z wyróżnieniem źródeł ataków na czerwono).
  - Oś czasu rozkładu godzinowego z obsługą kółka myszy, gestów dotykowych, przesuwania (Pan) i paska narzędziowego.
  - Wykresy kołowe i słupkowe (Kraje, Statusy HTTP, Operatorzy/ASN, Kategorie botów).
  - Pełne, przeszukiwalne tabele DataTables ze stronicowaniem i sortowaniem.
- **Zoptymalizowany dla Środowisk Produkcyjnych Linux:** Bezpieczny odczyt rosnących plików logów (kontrola snapshotu offsetu), natywna obsługa plików skompresowanych `.gz` oraz szybki cache JSON.

---

## Wymagania i Instalacja

### Wymagania systemowe
- Python 3.8 lub nowszy
- System operacyjny: Linux (zalecany na produkcji) lub Windows / macOS

### Instalacja bibliotek Python
Zainstaluj wymagane pakiety za pomocą menedżera `pip`:

```bash
pip install geoip2 numpy
```

### Bazy danych GeoIP
Program korzysta z bezpłatnych baz MaxMind GeoLite2 w formacie `.mmdb`:
- `GeoLite2-Country.mmdb` (kraj pochodzenia i geolokalizacja)
- `GeoLite2-ASN.mmdb` (dostawca Internetu / organizacja ASN)

Bazy są automatycznie wyszukiwane w katalogu roboczym skryptu lub w standardowych ścieżkach systemowych Linux:
- `/usr/share/GeoIP/`
- `/var/lib/GeoIP/`
- `/etc/httpd/`
- `/etc/apache2/`

---

## Szybki Start

### Podstawowe uruchomienie na serwerze Linux
Domyślnie program przeszukuje katalog `/var/log/httpd` (lub bieżący) w poszukiwaniu plików logów:

```bash
python3 web_traffic_analyzer.py
```

### Analiza konkretnego pliku lub katalogu z maską
```bash
python3 web_traffic_analyzer.py -p /var/log/httpd -m "access_log*" -o /var/www/html/raport.html
```

---

## Parametry Wiersza Poleceń (CLI)

| Parametr krótki | Parametr długi | Domyślna wartość | Opis |
| :--- | :--- | :--- | :--- |
| `-p` | `--path` | `/var/log/httpd` | Ścieżka do katalogu z logami serwera lub do pojedynczego pliku logu. |
| `-m` | `--mask` | `smartsite.mazovia.app-access.log*` | Maska nazw plików logów we wskazanym katalogu (np. `*access*.log*`, `access_log*`). |
| `-l` | `--log` | `None` | Bezpośredni wzorzec pliku (kompatybilność wsteczna, np. `logs/*.log`). |
| `-o` | `--output` / `--output-html` | `traffic_analysis_report.html` | Ścieżka docelowa wyjściowego raportu HTML lub katalog na wszystkie artefakty. |
| `-b` | `--output-blacklist` | `blacklist_ips.txt` | Nazwa lub ścieżka pliku wyjściowego z blacklistą adresów IP. |
| | `--output-apache-rules` | `apache_block_rules.conf` | Nazwa lub ścieżka pliku z regułami blokującymi dla Apache. |
| `-d` | `--date` | `None` (wszystkie) | Filtrowanie wpisów po dacie w formacie `DD/Mon/YYYY` (np. `23/Oct/2026`). |
| `-w` | `--whitelist` | `None` | Dodatkowe adresy IP lub podsieci CIDR do białej listy (oddzielone przecinkami). |
| | `--whitelist-file` | `None` | Ścieżka do pliku tekstowego z adresami IP/CIDR zaufanymi (jeden wpis na linię). |
| | `--url-threshold-mult` | `2.0` | Mnożnik mediany dla wyznaczania progu nadmiernego ruchu na URL. |
| | `--ip-threshold-mult` | `2.0` | Mnożnik mediany dla wyznaczania progu anomalnego ruchu dla IP. |
| | `--min-url-threshold` | `20.0` | Minimalna bezwzględna liczba żądań wymagana do zakwalifikowania URL jako anomalii. |
| | `--min-ip-threshold` | `20.0` | Minimalna bezwzględna liczba żądań wymagana do zakwalifikowania IP jako anomalii. |
| | `--cache-file` | `.traffic_analyzer_cache.json` | Ścieżka do pliku pamięci podręcznej parsowania logów. |
| | `--no-cache` | `False` | Wyłącza pamięć podręczną (wymusza pełne parsowanie wszystkich plików od zera). |
| | `--clear-cache` | `False` | Czyści istniejący plik pamięci podręcznej przed uruchomieniem analizy. |
| | `--country-db` | `GeoLite2-Country.mmdb` | Własna ścieżka do bazy `GeoLite2-Country.mmdb`. |
| | `--asn-db` | `GeoLite2-ASN.mmdb` | Własna ścieżka do bazy `GeoLite2-ASN.mmdb`. |
| | `--max-lines` | `None` | Limit linii logu do przetworzenia (użyteczne przy szybkich testach na wielogigabajtowych plikach). |

---

## Przykłady Użycia

### 1. Standardowa analiza produkcyjna z zapisem do katalogu publicznego WWW
```bash
python3 web_traffic_analyzer.py \
    -p /var/log/httpd \
    -m "access_log*" \
    -o /var/www/html/security/traffic_report.html
```

### 2. Wykluczenie własnych adresów IP / sieci biurowej (Biała lista)
```bash
python3 web_traffic_analyzer.py \
    -p /var/log/httpd \
    -w "217.153.27.58,192.168.1.0/24,10.0.0.0/8" \
    -o raport.html
```

### 3. Analiza logów z wybranego dnia
```bash
python3 web_traffic_analyzer.py \
    -p logs/ \
    -m "*.log" \
    -d "23/Oct/2026"
```

### 4. Wymuszenie ponownego przetworzenia bez pamięci podręcznej (No-Cache)
```bash
python3 web_traffic_analyzer.py -p logs/ --no-cache
```

---

## Zastosowane Algorytmy i Metodologia

Program realizuje wieloetapowy potok analityczny (*pipeline*), łączący metody statystyki nieparametrycznej, analizy behawioralnej i heurystyki cyberbezpieczeństwa.

```
       [ Pliki Logów Apache (tekstowe / .gz) ]
                          │
                          ▼
 ┌──────────────────────────────────────────────────┐
 │ 1. Filtrowanie i Normalizacja                    │
 │  - Wykluczenie adresów IP z Whitelist (CIDR)     │
 │  - Podział: Żądania Dynamiczne vs Statyczne      │
 │  - Snapshot rozmiaru plików (ochrona live-tail)  │
 └────────────────────────┬─────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────┐
 │ 2. Dynamiczne Progi Statystyczne (2 × Mediana)   │
 │  - Próg dla URL-i: max(2 * Mediana, 20)          │
 │  - Próg dla Sekcji: max(2 * Mediana, 40)         │
 │  - Próg dla IP: max(2 * Mediana, 20)             │
 └────────────────────────┬─────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────┐
 │ 3. Identyfikacja i Wzbogacanie Danych IP         │
 │  - Offline GeoIP (Kraj, Miasto, Współrzędne)     │
 │  - Operator sieci i ASN (MaxMind GeoLite2)       │
 │  - Klasyfikacja User-Agent (Wyszukiwarki / Boty) │
 └────────────────────────┬─────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────┐
 │ 4. Silnik Oceny Zagrożeń (Threat Score 0–100%)   │
 │  - Błędy HTTP 500/403/429 (Error Rate > 15%)     │
 │  - Narzędzia skryptowe CLI (cURL, urllib itp.)   │
 │  - Zautomatyzowane przeglądarki Headless         │
 │  - Brak pobierania zasobów CSS/JS/grafik         │
 │  - Centra danych / chmury (Azure, GCP, AWS itp.) │
 └────────────────────────┬─────────────────────────┘
                          │
                          ▼
 ┌──────────────────────────────────────────────────┐
 │ 5. Eksport i Generowanie Wyników                 │
 │  - Interaktywny Raport HTML z Mapami Leaflet     │
 │  - Blacklista IP (blacklist_ips.txt)             │
 │  - Reguły ochronne Apache (apache_block_rules)   │
 └──────────────────────────────────────────────────┘
```

---

### 1. Normalizacja i Filtrowanie Zasobów Statycznych

Ruch sieciowy generowany przez standardowe przeglądarki internetowe obejmuje dużą liczbę zapytań pomocniczych o pliki graficzne (`.png`, `.jpg`, `.webp`), arkusze stylów (`.css`), skrypty (`.js`), fonty (`.woff2`) czy mapy źródeł. 

- **Filtrowanie:** Wszystkie zasoby o rozszerzeniach statycznych są rejestrowane na poziomie metryk ogólnych, lecz **wykluczane z agregacji obciążenia podstron**.
- **Identyfikacja scraperów:** Prawdziwy użytkownik pobiera stronę HTML wraz z towarzyszącymi jej assetami statycznymi. Boty i scrapery pobierają niemal wyłącznie surowy kod HTML (stosunek pobrań statycznych do dynamicznych $< 5\%$), co stanowi kluczowy wskaźnik behawioralny.

---

### 2. Dynamiczne Progi Ruchu (Reguła 2 × Mediana)

W analizie ruchu sieciowego średnia arytmetyczna ($\mu$) jest wysoce podatna na zakłócenia przez pojedyncze ekstremalne anomalie (np. milion zapytań z jednego bota zawyża średnią dla całej domeny). Dlatego program stosuje **medianę** ($\text{Med}$), będącą odporną miarą tendencji centralnej:

$$\text{Próg URL} = \max\left(2 \times \text{Mediana}(\text{Żądania dla wszystkich URL}), 20\right)$$

$$\text{Próg IP} = \max\left(2 \times \text{Mediana}(\text{Żądania stron dla wszystkich IP odpytujących przeciążone URL}), 20\right)$$

Adresy IP i adresy URL przekraczające wyznaczone progi są natychmiast kwalifikowane do szczegółowej inspekcji.

---

### 3. Klasyfikacja Behawioralna i Sygnaturowa (User-Agent)

Każde zapytanie analizowane jest pod kątem sygnatury `User-Agent` i przypisywane do jednej z kategorii:

1. **Oficjalne Wyszukiwarki (Search Engine Bots):** Googlebot, Bingbot, Yandex, DuckDuckGo, Baidu, Seznam itp. (oznaczane kolorem zielonym / bezpieczne).
2. **Boty SEO i AI Scrapery:** Semrush, Ahrefs, DotBot, ByteSpider, GPTBot, ClaudeBot, CCBot itp.
3. **Podejrzane Narzędzia Automatyzacji i CLI:** `HeadlessChrome`, `Puppeteer`, `Playwright`, `Selenium`, `Python-urllib`, `Python Requests`, `aiohttp`, `curl`, `Go-http-client`, `Postman`, `Wget`, `Scrapy` oraz pusty nagłówek User-Agent (`-`).
4. **Ruch Użytkowników / Przeglądarek:** Chrome, Firefox, Safari, Edge, Opera.

---

### 4. Algorytm Scoringu Zagrożeń (Threat Score 0–100%)

Dla każdego adresu IP, który przekroczył próg anomalnego ruchu, wyliczany jest addytywny wskaźnik zagrożenia **Threat Score** na podstawie zestawu wag behawioralno-infrastrukturalnych:

| Kryterium / Symptom Zagrożenia | Waga Punktowa | Uzasadnienie |
| :--- | :---: | :--- |
| **Złośliwy / podejrzany User-Agent** | **+45 pkt** | Sygnatury `HeadlessChrome`, skrypty Python, cURL, Go-client, brak nagłówka UA. |
| **Narzędzie skryptowe / scraper AI** | **+25 pkt** | Zautomatyzowane narzędzia niebędące wyszukiwarkami. |
| **Brak pobierania zasobów statycznych** | **+25 pkt** | Pobrano $> 50$ podstron dynamicznych przy $< 5\%$ pobranych grafik/CSS/JS (behawior scrapera). |
| **Wysoki wskaźnik błędów serwera** | **+20 pkt** | Ponad $15\%$ odpowiedzi to kody HTTP 500 (awaria aplikacji), 403 (próby włamań) lub 429 (przekroczenie limitów). |
| **Pochodzenie z chmury / Datacenter** | **+20 pkt** | Ruch pochodzący z centrów danych (Microsoft Azure, AWS, Google Cloud, Hetzner, OVH, DigitalOcean itp.) zamiast sieci konsumenckich (ISP). |

#### Warunek kwalifikacji do Blacklisty (`blacklist_ips.txt`):
Adres IP zostaje zakwalifikowany do natychmiastowej blokady, jeżeli:
$$\text{Threat Score} \ge 50\% \quad \lor \quad (\text{Narzędzie CLI / Brak UA} \land \text{Ruch} \ge \text{Próg})$$
*(przy automatycznym wykluczeniu adresów z Białej Listy oraz sieci prywatnych RFC 1918).*

---

### 5. Zautomatyzowana Diagnoza i Werdykt Globalny

Po zakończeniu agregacji silnik diagnostyczny dokonuje syntezy całego zbioru danych i generuje jeden z werdyktów:
- 🚨 **ATAK SIECIOWY / SZTUCZNE OBCIĄŻENIE (DDoS / Scraper Botnet):** Wykryto masowy ruch z adresów o wysokim Threat Score generujących błędy 500/403.
- ⚠️ **WZMOŻONY RUCH AUTOMATYCZNY / CRAWLERY:** Ruch zdominowany przez boty komercyjne, indeksowanie SEO lub AI Scrapery bez cech destrukcyjnych.
- ℹ️ **NATURALNY WZROST ZAINTERESOWANIA (Ruch Prawidłowy):** Wzrost zapytań pochodzi od rzeczywistych użytkowników z dominacją polskich operatorów telekomunikacyjnych i prawidłową strukturą pobierania zasobów.

---

### 6. Mechanizm Pracy na Żywym Serwerze i Pamięć Podręczna (Cache)

- **Ochrona przed nieskończonym czytaniem (Live-Tail Safe):** Podczas pracy na aktywnym serwerze HTTPD pliki logów stale rosną. Program w momencie startu wykonuje migawkę (`os.stat().st_size`) i kończy parsowanie dokładnie na zapamiętanym offsecie, co zapobiega pętlom i zawieszeniu analizy.
- **Pamięć podręczna (`.traffic_analyzer_cache.json`):** W przypadku analizowania wielu plików historycznych lub zrotowanych archiwów `.gz`, skrót metadanych (rozmiar, `mtime`, filtr daty, konfiguracja) jest zapisywany w cache. Ponowne uruchomienie analizy na milionach wpisów skraca czas wykonania z kilkunastu sekund do poniżej **0.5 sekundy**.

---

## Generowane Pliki i Raporty

Po zakończeniu analizy w katalogu docelowym generowane są 3 kluczowe artefakty:

### 1. `traffic_analysis_report.html`
Nowoczesny, samodzielny dashboard HTML zoptymalizowany pod kątem przeglądania lokalnego (`file://`) oraz przez serwer WWW.
- **Wykres osi czasu:** W pełni interaktywny wykres liniowy z możliwością płynnego powiększania kółkiem myszy/gestami oraz nawigacji przyciskami (←, →, +, -, ↺).
- **Mapy Leaflet:** Wizualizacja geograficzna z zaznaczeniem źródeł złośliwego ruchu kolorem czerwonym.
- **Dedykowana tabela Blacklist:** Zestawienie zidentyfikowanych agresorów z dokładnym wykazem powodów blokady.
- **Kompletna baza IP:** Przeszukiwalna tabela wszystkich adresów ponad progiem z paginacją DataTables.

### 2. `blacklist_ips.txt`
Czysty plik tekstowy zawierający listę unikalnych złośliwych adresów IP (wraz z komentarzami o kraju, operatorze i Threat Score). Plik można bezpośrednio załadować do reguł firewall:

```bash
# Przykład blokady w Linux iptables / ipset:
ipset create blacklist hash:ip
while read ip; do [[ ! "$ip" =~ ^# ]] && ipset add blacklist "$ip"; done < blacklist_ips.txt
iptables -I INPUT -m set --match-set blacklist src -j DROP
```

### 3. `apache_block_rules.conf`
Gotowy plik konfiguracyjny do dołączenia do konfiguracji Apache VirtualHost (`Include /path/to/apache_block_rules.conf`):

```apache
# Blokada adresów IP (Apache 2.4+)
<RequireAll>
    Require all granted
    Require not ip 20.207.202.183
    Require not ip 104.47.18.190
    ...
</RequireAll>

# Blokada złośliwych narzędzi i scraperów
BrowserMatchNoCase "HeadlessChrome" block_bad_bot
BrowserMatchNoCase "Python-urllib" block_bad_bot
Order Allow,Deny
Allow from all
Deny from env=block_bad_bot
```

---

## Licencja i Bezpieczeństwo

Program przetwarza logi w trybie **tylko do odczytu** – nie modyfikuje oryginalnych plików serwera ani nie wymaga uprawnień roota do samej analizy. Geolokalizacja odbywa się w 100% lokalnie, co gwarantuje pełną prywatność i zgodność z RODO/GDPR.
