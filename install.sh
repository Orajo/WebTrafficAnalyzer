#!/usr/bin/env bash
#
# install.sh - Skrypt instalacyjny dla Web Traffic Analyzer & DDoS / Bot Detector
#
# Sprawdza, czy w systemie są dostępne wymagane komponenty (Python 3, pip,
# biblioteki `geoip2` i `numpy`, plik konfiguracyjny `config.py`), a następnie
# doinstalowuje wyłącznie to, czego faktycznie brakuje. Bezpieczny do
# wielokrotnego uruchamiania (idempotentny).
#
# Użycie:
#   chmod +x install.sh
#   ./install.sh
#
# Opcje:
#   --system      instaluj pakiety Python globalnie (bez virtualenv)
#   --venv DIR    utwórz/użyj wirtualnego środowiska w podanym katalogu
#                 (domyślnie: .venv, jeśli nie podano --system)
#   -h, --help    wyświetl pomoc
#
set -euo pipefail

# ------------------------------------------------------------------------------
# Kolory i pomocnicze funkcje do logowania
# ------------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET='\033[0m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'
    C_RED='\033[0;31m'; C_BLUE='\033[0;34m'
else
    C_RESET=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_BLUE=''
fi

log_info()  { echo -e "${C_BLUE}[INFO]${C_RESET}  $*"; }
log_ok()    { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
log_warn()  { echo -e "${C_YELLOW}[UWAGA]${C_RESET} $*"; }
log_err()   { echo -e "${C_RED}[BŁĄD]${C_RESET}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

USE_VENV=1
VENV_DIR=".venv"

# ------------------------------------------------------------------------------
# Parsowanie argumentów
# ------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --system)
            USE_VENV=0
            shift
            ;;
        --venv)
            VENV_DIR="${2:-.venv}"
            USE_VENV=1
            shift 2
            ;;
        -h|--help)
            grep '^#' "$0" | sed -e '1d' -e 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            log_err "Nieznana opcja: $1"
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# 1. Sprawdzenie interpretera Python 3 (>= 3.8)
# ------------------------------------------------------------------------------
log_info "Sprawdzanie interpretera Python 3..."

PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version_check=$("$candidate" -c 'import sys; print(1 if sys.version_info >= (3, 8) else 0)' 2>/dev/null || echo 0)
        if [ "$version_check" = "1" ]; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    log_warn "Nie znaleziono odpowiedniego interpretera Python 3.8+ w systemie."
    log_info "Próba instalacji Pythona 3 za pomocą menedżera pakietów systemu..."

    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y python3 python3-pip python3-venv
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 python3-pip
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y python3 python3-pip
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y python3 python3-pip
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add --no-cache python3 py3-pip
    else
        log_err "Nie udało się automatycznie zainstalować Pythona 3 - nieznany menedżer pakietów."
        log_err "Zainstaluj ręcznie Python 3.8+ i uruchom ten skrypt ponownie."
        exit 1
    fi

    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PYTHON_BIN="$candidate"
            break
        fi
    done

    if [ -z "$PYTHON_BIN" ]; then
        log_err "Instalacja Pythona 3 nie powiodła się. Przerwano."
        exit 1
    fi
fi

PYTHON_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
log_ok "Znaleziono Python $PYTHON_VERSION ($PYTHON_BIN)."

# ------------------------------------------------------------------------------
# 2. Sprawdzenie modułu pip oraz venv
# ------------------------------------------------------------------------------
log_info "Sprawdzanie modułu pip..."

if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    log_warn "Moduł pip nie jest dostępny - próba instalacji przez ensurepip..."
    if ! "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y python3-pip
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y python3-pip
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y python3-pip
        fi
    fi
fi

if "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    log_ok "pip jest dostępny ($("$PYTHON_BIN" -m pip --version))."
else
    log_err "Nie udało się zapewnić działającego modułu pip. Przerwano."
    exit 1
fi

# ------------------------------------------------------------------------------
# 3. (Opcjonalnie) utworzenie / aktywacja wirtualnego środowiska
# ------------------------------------------------------------------------------
PIP_CMD=("$PYTHON_BIN" -m pip)

if [ "$USE_VENV" = "1" ]; then
    if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/python" ]; then
        log_ok "Wirtualne środowisko '$VENV_DIR' już istnieje - używam go."
    else
        log_info "Tworzenie wirtualnego środowiska w '$VENV_DIR'..."
        if ! "$PYTHON_BIN" -m venv "$VENV_DIR" 2>/dev/null; then
            log_warn "Moduł venv niedostępny - próba doinstalowania pakietu python3-venv..."
            if command -v apt-get >/dev/null 2>&1; then
                sudo apt-get install -y python3-venv
            fi
            "$PYTHON_BIN" -m venv "$VENV_DIR"
        fi
        log_ok "Utworzono wirtualne środowisko '$VENV_DIR'."
    fi
    PYTHON_BIN="$VENV_DIR/bin/python"
    PIP_CMD=("$PYTHON_BIN" -m pip)
    log_info "Aby ręcznie aktywować środowisko w przyszłości: source $VENV_DIR/bin/activate"
else
    log_info "Instalacja pakietów w trybie systemowym (--system), bez virtualenv."
fi

# ------------------------------------------------------------------------------
# 4. Sprawdzenie i instalacja wymaganych bibliotek Python (geoip2, numpy)
# ------------------------------------------------------------------------------
REQUIRED_PACKAGES=("geoip2" "numpy")

MISSING_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    log_info "Sprawdzanie biblioteki '$pkg'..."
    if "$PYTHON_BIN" -c "import $pkg" >/dev/null 2>&1; then
        installed_version="$("$PYTHON_BIN" -c "import $pkg; print(getattr($pkg, '__version__', 'nieznana'))" 2>/dev/null || echo "nieznana")"
        log_ok "Biblioteka '$pkg' jest już zainstalowana (wersja: $installed_version)."
    else
        log_warn "Biblioteka '$pkg' nie jest zainstalowana - zostanie doinstalowana."
        MISSING_PACKAGES+=("$pkg")
    fi
done

if [ "${#MISSING_PACKAGES[@]}" -gt 0 ]; then
    log_info "Instalowanie brakujących bibliotek: ${MISSING_PACKAGES[*]}..."
    "${PIP_CMD[@]}" install --upgrade pip >/dev/null 2>&1 || true
    "${PIP_CMD[@]}" install "${MISSING_PACKAGES[@]}"
    log_ok "Zainstalowano brakujące biblioteki: ${MISSING_PACKAGES[*]}."
else
    log_ok "Wszystkie wymagane biblioteki Python są już zainstalowane."
fi

# ------------------------------------------------------------------------------
# 5. Sprawdzenie pliku konfiguracyjnego config.py
# ------------------------------------------------------------------------------
log_info "Sprawdzanie pliku konfiguracyjnego config.py..."

if [ -f "config.py" ]; then
    log_ok "Plik config.py już istnieje - pozostawiam bez zmian."
else
    if [ -f "config.dist.py" ]; then
        cp config.dist.py config.py
        log_ok "Utworzono config.py na podstawie config.dist.py."
        log_warn "Dostosuj config.py (biała lista IP, ścieżka/maska logów) do swojego środowiska przed uruchomieniem."
    else
        log_warn "Brak pliku config.dist.py - nie można automatycznie utworzyć config.py."
    fi
fi

# ------------------------------------------------------------------------------
# 6. Sprawdzenie baz danych GeoLite2 (.mmdb)
# ------------------------------------------------------------------------------
log_info "Sprawdzanie baz danych GeoLite2..."

GEOIP_SEARCH_PATHS=(
    "."
    "/usr/share/GeoIP"
    "/var/lib/GeoIP"
    "/etc/httpd"
    "/etc/apache2"
)

check_mmdb() {
    local filename="$1"
    for dir in "${GEOIP_SEARCH_PATHS[@]}"; do
        if [ -f "$dir/$filename" ]; then
            log_ok "Znaleziono $filename w $dir"
            return 0
        fi
    done
    log_warn "Nie znaleziono pliku $filename w żadnej ze standardowych lokalizacji (${GEOIP_SEARCH_PATHS[*]})."
    log_warn "Pobierz bazę ręcznie z https://www.maxmind.com (wymaga darmowego konta) i umieść ją w katalogu skryptu."
    return 1
}

check_mmdb "GeoLite2-Country.mmdb" || true
check_mmdb "GeoLite2-ASN.mmdb" || true

# ------------------------------------------------------------------------------
# Podsumowanie
# ------------------------------------------------------------------------------
echo
log_ok "Instalacja zakończona."
echo
if [ "$USE_VENV" = "1" ]; then
    echo "Aby uruchomić program, aktywuj środowisko wirtualne i wywołaj skrypt:"
    echo "  source $VENV_DIR/bin/activate"
    echo "  python3 web_traffic_analyzer.py"
else
    echo "Aby uruchomić program:"
    echo "  python3 web_traffic_analyzer.py"
fi
