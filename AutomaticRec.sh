#!/bin/bash

# Bash 4.3+ required (wait -n support)
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    echo "[-] This script requires Bash 4.3 or higher. Current: $BASH_VERSION" >&2
    exit 1
fi

banner="

    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                        AutomaticRec                          ║
    ║             reverse recon · enum · vulnerability scan        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
"

silent="false"
COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_RESET="\033[0m"

# Load optional config file for env vars (e.g., CHAOS_KEY)
# readlink -f: si el script está en /usr/bin vía symlink, resolvemos al directorio real (recon_inverso.py, conf).
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/AutomaticRec.conf}"
RECON_SCRIPT="${SCRIPT_DIR}/recon_inverso.py"
if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    set +a
fi

LOG_FILE=""

log() {
    local msg="$1"
    if [[ "$silent" != "true" ]]; then
        LAST_OUTPUT_TS=$(date +%s)
        printf "\r\033[2K" >&2
        echo -e "$msg"
        [[ -n "$TICKER_PID" ]] && ticker_render_once
    fi
    if [[ "$create_log" == "true" && -n "$LOG_FILE" ]]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE"
    fi
}

warn() {
    LAST_OUTPUT_TS=$(date +%s)
    printf "\r\033[2K" >&2
    echo -e "$1" >&2
    [[ -n "$TICKER_PID" ]] && ticker_render_once
    if [[ -n "$LOG_FILE" ]]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE"
    fi
}

spinner_pid=""
spinner_msg=""
CHILD_PIDS=()
MAIN_PID=$$
START_TS=""
PHASE_MSG="Starting Reverse Recon"
TICKER_PID=""
PHASE_FILE="/tmp/automaticrec_phase_${MAIN_PID}.txt"
TICKER_WIDTH=20
LAST_OUTPUT_TS=0
IDLE_THRESHOLD=10
TICKER_SUPPRESS=0
SUPPRESS_FILE="/tmp/automaticrec_suppress_${MAIN_PID}.txt"
INTERRUPTED=0

# Mata recursivamente descendientes (nietos de bash: nuclei, httpx, rush/curl, waymore, etc.)
# sig: TERM o KILL (9)
kill_descendants_of() {
    local parent=$1
    local sig=${2:-TERM}
    local child
    for child in $(pgrep -P "$parent" 2>/dev/null); do
        kill_descendants_of "$child" "$sig"
        kill -s "$sig" "$child" 2>/dev/null || true
    done
}

cleanup_on_interrupt() {
    INTERRUPTED=1
    [[ "$silent" != "true" ]] && echo -e "\n${COLOR_YELLOW}[!] Interrupted by user, cleaning up...${COLOR_RESET}"
    trap - INT TERM
    # Kill registered child pids
    if [[ ${#CHILD_PIDS[@]} -gt 0 ]]; then
        for pid in "${CHILD_PIDS[@]}"; do
            kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
        done
    fi
    # Árbol completo (antes: solo pkill -P → hijos directos; pipelines dejan nietos vivos)
    kill_descendants_of "$MAIN_PID" TERM
    pkill -TERM -P "$MAIN_PID" 2>/dev/null || true
    sleep 0.4
    kill_descendants_of "$MAIN_PID" KILL
    pkill -KILL -P "$MAIN_PID" 2>/dev/null || true
    spinner_stop
    if [[ -n "$TICKER_PID" ]]; then
        kill "$TICKER_PID" 2>/dev/null || true
        wait "$TICKER_PID" 2>/dev/null || true
    fi
    rm -f "$PHASE_FILE" 2>/dev/null || true
    rm -f "$SUPPRESS_FILE" 2>/dev/null || true
    exit 130
}

cleanup_on_exit() {
    spinner_stop
    if [[ -n "$TICKER_PID" ]]; then
        kill "$TICKER_PID" 2>/dev/null || true
        wait "$TICKER_PID" 2>/dev/null || true
    fi
    rm -f "$PHASE_FILE" 2>/dev/null || true
    rm -f "$SUPPRESS_FILE" 2>/dev/null || true
}

trap cleanup_on_interrupt INT TERM
trap cleanup_on_exit EXIT

spinner_start() {
    spinner_msg="$1"
    [[ "$silent" == "true" ]] && return 0
    (
        local spin='|/-\'
        local i=0
        while true; do
            i=$(( (i+1) % 4 ))
            printf "\r[%c] %s" "${spin:$i:1}" "$spinner_msg"
            sleep 0.2
        done
    ) &
    spinner_pid=$!
}

spinner_stop() {
    [[ "$silent" == "true" ]] && return 0
    if [[ -n "$spinner_pid" ]]; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null
        spinner_pid=""
        printf "\r%s\r" " "
        echo ""
    fi
}

status_line() {
    [[ "$silent" == "true" ]] && return 0
    local msg="$1"
    printf "\r\033[2K%s" "$msg" >&2
}

status_done() {
    [[ "$silent" == "true" ]] && return 0
    printf "\r\033[2K%s\r\n" "$1" >&2
}

format_elapsed() {
    local start_ts="$1"
    local now_ts
    now_ts=$(date +%s)
    local diff=$((now_ts - start_ts))
    local mins=$((diff / 60))
    local secs=$((diff % 60))
    printf "%02d:%02d" "$mins" "$secs"
}

set_phase() {
    PHASE_MSG="$1"
    echo "$PHASE_MSG" > "$PHASE_FILE" 2>/dev/null || true
}

ticker_start() {
    [[ "$silent" == "true" ]] && return 0
    START_TS=$(date +%s)
    LAST_OUTPUT_TS=$(date +%s)
    echo "$PHASE_MSG" > "$PHASE_FILE" 2>/dev/null || true
    echo "0" > "$SUPPRESS_FILE" 2>/dev/null || true
    (
        while true; do
            local elapsed
            local phase
            local now_ts
            local suppress
            elapsed=$(format_elapsed "$START_TS")
            phase=$(cat "$PHASE_FILE" 2>/dev/null || echo "$PHASE_MSG")
            now_ts=$(date +%s)
            suppress=$(cat "$SUPPRESS_FILE" 2>/dev/null || echo "0")
            if [[ "$suppress" == "1" ]]; then
                sleep 1
                continue
            fi
            if (( TICKER_SUPPRESS == 0 )) && (( now_ts - LAST_OUTPUT_TS >= IDLE_THRESHOLD )); then
                printf "\r${COLOR_CYAN}Time:${COLOR_RESET} %s | %s" \
                    "$elapsed" "$phase" >&2
            else
                printf "\r\033[2K" >&2
            fi
            sleep 1
        done
    ) &
    TICKER_PID=$!
}

ticker_start_force() {
    [[ "$silent" != "true" ]] && return 0
    START_TS=$(date +%s)
    LAST_OUTPUT_TS=$(date +%s)
    echo "$PHASE_MSG" > "$PHASE_FILE" 2>/dev/null || true
    echo "0" > "$SUPPRESS_FILE" 2>/dev/null || true
    (
        while true; do
            local elapsed
            local phase
            local suppress
            elapsed=$(format_elapsed "$START_TS")
            phase=$(cat "$PHASE_FILE" 2>/dev/null || echo "$PHASE_MSG")
            suppress=$(cat "$SUPPRESS_FILE" 2>/dev/null || echo "0")
            if [[ "$suppress" == "1" ]]; then
                sleep 1
                continue
            fi
            printf "\r${COLOR_CYAN}Time:${COLOR_RESET} %s | %s" \
                "$elapsed" "$phase" >&2
            sleep 1
        done
    ) &
    TICKER_PID=$!
}

ticker_suppress_on() {
    TICKER_SUPPRESS=1
    printf "\r\033[2K" >&2
    echo "1" > "$SUPPRESS_FILE" 2>/dev/null || true
}

ticker_suppress_off() {
    TICKER_SUPPRESS=0
    LAST_OUTPUT_TS=$(date +%s)
    echo "0" > "$SUPPRESS_FILE" 2>/dev/null || true
}

ticker_render_once() {
    [[ "$silent" == "true" ]] && return 0
    [[ -z "$START_TS" ]] && return 0
    printf "\r\033[2K" >&2
}

ticker_stop() {
    [[ "$silent" == "true" ]] && return 0
    if [[ -n "$TICKER_PID" ]] && kill -0 "$TICKER_PID" 2>/dev/null; then
        kill -TERM "$TICKER_PID" 2>/dev/null || true
        local _w=0
        while kill -0 "$TICKER_PID" 2>/dev/null && [[ $_w -lt 25 ]]; do
            sleep 0.2
            _w=$((_w + 1))
        done
        kill -KILL "$TICKER_PID" 2>/dev/null || true
        wait "$TICKER_PID" 2>/dev/null || true
    fi
    TICKER_PID=""
    printf "\r\033[2K" >&2
    echo "" >&2
    rm -f "$PHASE_FILE" 2>/dev/null || true
    rm -f "$SUPPRESS_FILE" 2>/dev/null || true
}

help_message() {
    echo "Usage: $0 [-h] [-a] [-l file] [-u url] [-o output] [-s] [-r]"
    echo ""
    echo "Options:"
    echo "  -h         Show this help message"
    echo "  -a         Perform full scan including vulnerability scanning"
    echo "  -l file    Use a file containing a list of URLs"
    echo "  -u url     Scan a single URL (bare domain, e.g. example.com)"
    echo "  -o output  Specify output folder name"
    echo "  -s         Perform only subdomain enumeration"
    echo "  -r         Perform reconnaissance (subdomains + waymore URLs), but no vulnerability scans"
    echo "  -only      Use only the specified domain (no extra recon domains)"
    echo "  --recon-all-domains  Incluir del recon todos los apex del JSON (por defecto solo subdominios de -u)"
    echo "  -x list    Exclude domains/subdomains (CSV: a.com,b.a.com)"
    echo "  --silent   Silence screen output"
    echo "  --timeout N  Global timeout (seconds) for tools without one"
    echo "  -j N       Parallel targets (only with -l)"
    echo "  --refresh-cache  Ignore RapidDNS/crt.sh local cache"
    echo "  --log      Crear automaticrec.log bajo -o (por defecto no se crea)"
    echo "  --no-log   No crear automaticrec.log (comportamiento por defecto)"
    echo "  --recon-max-ips N            Max IPs from ASN (recon)"
    echo "  --recon-max-ips-reverse N    Max IPs for reverse DNS (recon)"
    echo "  --recon-max-domains-sub N    Max domains for subdomain search (recon)"
    echo "  --recon-max-ips-ec2 N        Max IPs for EC2 detection (recon)"
    echo "  --recon-threads N            Threads for recon_inverso"
    echo "  --recon-aws-cache-ttl N      AWS cache TTL (seconds)"
    echo "  --recon-skip-ownership-check Skip WHOIS ownership check (recon)"
    echo "  --no-reverse-recon       Skip recon_inverso.py (ASN/reverse IP; puede tardar mucho en .gov)"
    exit 1
}

# Default values
mode=""
output="scan_results"
only="false"
recon_all_domains="false"
exclude_csv=""
run_timeout="0"
max_jobs="1"
refresh_cache="false"
recon_max_ips=""
recon_max_ips_reverse=""
recon_max_domains_sub=""
recon_max_ips_ec2=""
recon_threads=""
recon_aws_cache_ttl=""
recon_skip_ownership="false"
no_reverse_recon="false"
create_log="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h) help_message ;;
        -a) mode="full"; shift ;;
        -l) url_list="$2"; shift 2 ;;
        -u) url="$2"; shift 2 ;;
        -o) output="$2"; shift 2 ;;
        -s) mode="subs"; shift ;;
        -r) mode="recon"; shift ;;
        -only|--only) only="true"; shift ;;
        -x) exclude_csv="$2"; shift 2 ;;
        -silent|--silent) silent="true"; shift ;;
        --timeout) run_timeout="$2"; shift 2 ;;
        -j) max_jobs="$2"; shift 2 ;;
        --refresh-cache) refresh_cache="true"; shift ;;
        --recon-max-ips) recon_max_ips="$2"; shift 2 ;;
        --recon-max-ips-reverse) recon_max_ips_reverse="$2"; shift 2 ;;
        --recon-max-domains-sub) recon_max_domains_sub="$2"; shift 2 ;;
        --recon-max-ips-ec2) recon_max_ips_ec2="$2"; shift 2 ;;
        --recon-threads) recon_threads="$2"; shift 2 ;;
        --recon-aws-cache-ttl) recon_aws_cache_ttl="$2"; shift 2 ;;
        --recon-skip-ownership-check) recon_skip_ownership="true"; shift ;;
        --no-reverse-recon) no_reverse_recon="true"; shift ;;
        --recon-all-domains) recon_all_domains="true"; shift ;;
        --log) create_log="true"; shift ;;
        --no-log) create_log="false"; shift ;;
        --) shift; break ;;
        \?) echo "Invalid option: $1" >&2; exit 1 ;;
        *) echo "Invalid option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$url" && -z "$url_list" ]]; then
    warn "${COLOR_RED}Error: You must specify either -u (URL) or -l (list file)${COLOR_RESET}"
    exit 1
fi

# Validate and normalize -u input (strip http/https://, trailing slashes, reject paths)
normalize_domain() {
    local raw="$1"
    # Strip protocol
    raw="${raw#http://}"
    raw="${raw#https://}"
    # Strip trailing slash and any path
    raw="${raw%%/*}"
    # Strip port (optional: keep port if needed, but subdomains won't have it)
    # Reject if empty or contains spaces
    if [[ -z "$raw" || "$raw" =~ [[:space:]] ]]; then
        echo "" && return 1
    fi
    echo "$raw"
}

if [[ -n "$url" ]]; then
    url_normalized=$(normalize_domain "$url")
    if [[ -z "$url_normalized" ]]; then
        warn "${COLOR_RED}Error: Invalid domain format for -u. Use bare domain (e.g. example.com)${COLOR_RESET}"
        exit 1
    fi
    if [[ "$url_normalized" != "$url" ]]; then
        warn "${COLOR_YELLOW}[!] Domain normalized: '$url' -> '$url_normalized'${COLOR_RESET}"
        url="$url_normalized"
    fi
fi

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
TIMEOUT_CMD=()
if [[ -n "$TIMEOUT_BIN" && "$run_timeout" -gt 0 ]]; then
    TIMEOUT_CMD=("$TIMEOUT_BIN" "$run_timeout")
fi

CURL_OPTS=(--connect-timeout 10 --max-time 30 --retry 2 --retry-delay 2 --retry-connrefused -s)

check_deps() {
    local missing=()
    local deps=(python3 assetfinder subfinder amass ffuf dnsx httpx curl)
    if [[ "$mode" == "recon" || "$mode" == "full" ]]; then
        deps+=(waymore)
    fi
    if [[ "$mode" == "full" ]]; then
        deps+=(nuclei qsreplace uro freq rush)
    fi
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "${COLOR_RED}[-] Missing dependencies: ${missing[*]}${COLOR_RESET}"
        exit 1
    fi
    if [[ "$run_timeout" -gt 0 && -z "$TIMEOUT_BIN" ]]; then
        warn "${COLOR_YELLOW}[!] timeout is not available, --timeout will be ignored${COLOR_RESET}"
    fi
}

check_deps

if [[ "$silent" != "true" ]]; then
    echo -e "${COLOR_CYAN}${banner}${COLOR_RESET}"
fi

# Initialize log file in output directory
if [[ "$create_log" == "true" ]]; then
    mkdir -p "$output"
    LOG_FILE="$output/automaticrec.log"
    # Silently initialize the log file
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] --- Scan started ---" > "$LOG_FILE"
fi

ticker_start
ticker_start_force
set_phase "Starting Reverse Recon"

normalize_excludes() {
    if [[ -z "$exclude_csv" ]]; then
        EXCLUDE_LIST=""
        return
    fi
    EXCLUDE_LIST=$(EXCLUDES_RAW="$exclude_csv" python3 - <<'PY'
import os
raw = os.environ.get("EXCLUDES_RAW", "")
items = [i.strip().lower() for i in raw.split(",")]
items = [i for i in items if i]
print(",".join(items))
PY
)
}

filter_exclusions() {
    local file="$1"
    [[ -z "$EXCLUDE_LIST" ]] && return 0
    [[ ! -s "$file" ]] && return 0
    [[ ! -f "$file" ]] && return 0
    EXCLUDE_LIST="$EXCLUDE_LIST" python3 - <<'PY' "$file"
import os, sys
path = sys.argv[1]
excludes = [e.strip().lower() for e in os.environ.get("EXCLUDE_LIST", "").split(",") if e.strip()]
if not excludes:
    raise SystemExit(0)
with open(path, "r") as f:
    lines = [l.strip() for l in f if l.strip()]
def is_excluded(d):
    d = d.lower()
    for ex in excludes:
        if d == ex or d.endswith("." + ex):
            return True
    return False
filtered = [l for l in lines if not is_excluded(l)]
with open(path, "w") as f:
    f.write("\n".join(filtered) + ("\n" if filtered else ""))
PY
}

# Solo conservar informes de vulns si tienen contenido; si no, eliminar al final
remove_empty_vuln_outputs() {
    local dir="$1"
    local v
    for v in nuclei.txt xss_vulnerables.txt cors.txt; do
        [[ -f "$dir/$v" && ! -s "$dir/$v" ]] && rm -f "$dir/$v"
    done
}

seed_for_target() {
    local seed_all="$1"
    local target="$2"
    local seed_target="$3"
    [[ ! -s "$seed_all" ]] && return 0
    python3 - <<'PY' "$seed_all" "$seed_target" "$target"
import sys
seed_all, seed_target, target = sys.argv[1], sys.argv[2], sys.argv[3].lower()
def belongs(d):
    d = d.lower()
    return d == target or d.endswith("." + target)
with open(seed_all, "r") as f:
    lines = [l.strip() for l in f if l.strip()]
filtered = [l for l in lines if belongs(l)]
with open(seed_target, "w") as f:
    f.write("\n".join(sorted(set(filtered))) + ("\n" if filtered else ""))
PY
}

get_recon_targets() {
    local target="$1"
    local recon_json="$2"
    local target_file="$3"
    if [[ "$only" == "true" || ! -s "$recon_json" ]]; then
        echo "$target" > "$target_file"
        return
    fi
    # Por defecto solo dominios bajo el mismo apex que -u (ej. api.tinder.com), no otros TLD (tinder.biz).
    # --recon-all-domains restaura el merge amplio del JSON.
    python3 - <<'PY' "$recon_json" "$target_file" "$target" "$recon_all_domains"
import json, sys
recon_json, target_file, main_domain, recon_all = sys.argv[1], sys.argv[2], sys.argv[3].strip().lower(), sys.argv[4].lower() in ("1", "true", "yes")
data = json.load(open(recon_json, "r"))
raw = [d.strip().lower() for d in data.get("dominios", []) if d and isinstance(d, str)]

def under_main(d: str, main: str) -> bool:
    return d == main or d.endswith("." + main)

if recon_all:
    targets = set(raw)
else:
    targets = {d for d in raw if under_main(d, main_domain)}

targets.add(main_domain)
with open(target_file, "w") as f:
    f.write("\n".join(sorted(targets)) + "\n")
PY
    if [[ ! -s "$target_file" ]]; then
        echo "$target" > "$target_file"
    fi
}

run_recon() {
    local target="$1"
    local recon_seed="$2"
    local recon_json="recon_${target}.json"
    mkdir -p "$output"
    if [[ "$no_reverse_recon" == "true" ]]; then
        log "${COLOR_YELLOW}[~] Reverse recon omitido (--no-reverse-recon) → solo enumeración + waymore${COLOR_RESET}"
        [[ -n "$recon_seed" ]] && : > "$recon_seed"
        return
    fi
    if [[ -x "$RECON_SCRIPT" || -f "$RECON_SCRIPT" ]]; then
        log "${COLOR_CYAN}[~] Reverse recon for $target (may take a few minutes)${COLOR_RESET}"
        set_phase "Reverse recon in progress"
        local cmd=(python3 "$RECON_SCRIPT" -u "$target" -o "$recon_seed")
        [[ -n "$recon_threads" ]] && cmd+=(-t "$recon_threads")
        [[ -n "$recon_max_ips" ]] && cmd+=(--max-ips "$recon_max_ips")
        [[ -n "$recon_max_ips_reverse" ]] && cmd+=(--max-ips-reverse "$recon_max_ips_reverse")
        [[ -n "$recon_max_domains_sub" ]] && cmd+=(--max-domains-sub "$recon_max_domains_sub")
        [[ -n "$recon_max_ips_ec2" ]] && cmd+=(--max-ips-ec2 "$recon_max_ips_ec2")
        [[ -n "$recon_aws_cache_ttl" ]] && cmd+=(--aws-cache-ttl "$recon_aws_cache_ttl")
        [[ "$recon_skip_ownership" == "true" ]] && cmd+=(--skip-ownership-check)
        local start_ts
        start_ts=$(date +%s)
        # Salida de recon a /dev/null (no fichero _recon_*_inverso.log; antes iba a log por ARG_MAX con stdout)
        "${cmd[@]}" >>/dev/null 2>&1 &
        local recon_pid=$!
        CHILD_PIDS+=("$recon_pid")
        while kill -0 "$recon_pid" 2>/dev/null; do
            [[ "$INTERRUPTED" -eq 1 ]] && break
            local elapsed
            elapsed=$(format_elapsed "$start_ts")
            set_phase "Reverse recon in progress"
            sleep 1
        done
        wait "$recon_pid" 2>/dev/null || true
        log "${COLOR_GREEN}[✓] Reverse recon finished (${elapsed})${COLOR_RESET}"
        log "${COLOR_CYAN}[~] Reverse recon finished for $target${COLOR_RESET}"
    else
        warn "${COLOR_RED}[-] recon_inverso.py not found at $RECON_SCRIPT${COLOR_RESET}"
    fi
}

# Solo FQDN == target o *.target (mismo criterio que grep "\.$target$"); evita mezclar otros TLD
# si grep "$target" coincide por subcadena o salida ruidosa de ffuf/dnsx.
host_in_scope() {
    local h="$1"
    local t="$2"
    [[ -n "$h" && -n "$t" ]] || return 1
    [[ "$h" == "$t" || "$h" == *."$t" ]]
}

scan_url() {
    local target=$1
    local seed_file=$2
    local folder="$output/$target"
    local cache_dir="$folder/cache"
    local rapiddns_cache="$cache_dir/rapiddns.html"
    local crt_cache="$cache_dir/crtsh.html"
    local subs_count=0
    local live_count=0
    local httpx_live_start
    local urls_count=0
    local nuclei_count=0
    local xss_count=0
    local cors_count=0

    mkdir -p "$folder"
    mkdir -p "$cache_dir"

    if [[ "$refresh_cache" == "true" ]]; then
        rm -f "$rapiddns_cache" "$crt_cache"
    fi

    if [[ -n "$seed_file" && -s "$seed_file" ]]; then
        cat "$seed_file" >> "$folder/final.txt"
    fi

    set_phase "assetfinder: enumerating subdomains"
    log "${COLOR_GREEN}[+] Enumerating subdomains with assetfinder...${COLOR_RESET}"
    assetfinder "$target" | grep "\.$target$" >> "$folder/final.txt"
    log "${COLOR_RED}Subdomains found:${COLOR_RESET} $(wc -l < "$folder/final.txt")"

    set_phase "subfinder: enumerating subdomains"
    log "${COLOR_GREEN}[+] Enumerating subdomains with subfinder...${COLOR_RESET}"
    subfinder -d "$target" -all -silent | grep "\.$target$" >> "$folder/final.txt"
    log "${COLOR_RED}Subdomains found:${COLOR_RESET} $(wc -l < "$folder/final.txt")"

    if command -v chaos >/dev/null 2>&1 && [[ -n "${CHAOS_KEY:-}" ]]; then
        set_phase "chaos: enumerating subdomains"
        log "${COLOR_GREEN}[+] Enumerating subdomains with chaos...${COLOR_RESET}"
        chaos -d "$target" -silent | grep "\.$target$" >> "$folder/final.txt"
        log "${COLOR_RED}Subdomains found:${COLOR_RESET} $(wc -l < "$folder/final.txt")"
    else
        if ! command -v chaos >/dev/null 2>&1; then
            log "${COLOR_YELLOW}[!] chaos not installed, skipping${COLOR_RESET}"
        elif [[ -z "${CHAOS_KEY:-}" ]]; then
            log "${COLOR_YELLOW}[!] CHAOS_KEY not set, skipping chaos${COLOR_RESET}"
        fi
    fi

    set_phase "RapidDNS: enumerating subdomains"
    log "${COLOR_GREEN}[+] Enumerating subdomains with RapidDNS...${COLOR_RESET}"
    if [[ ! -s "$rapiddns_cache" ]]; then
        curl "${CURL_OPTS[@]}" "https://rapiddns.io/subdomain/$target?full=1" > "$rapiddns_cache"
    fi
    sed -e 's/<[^>]*>//g' < "$rapiddns_cache" | \
        grep -oP "([a-zA-Z0-9_-]+\\.$target)" | grep "\.$target$" | sort -u >> "$folder/final.txt"
    log "${COLOR_RED}Subdomains found:${COLOR_RESET} $(wc -l < "$folder/final.txt")"

    set_phase "crt.sh: enumerating subdomains"
    log "${COLOR_GREEN}[+] Enumerating subdomains with crt.sh...${COLOR_RESET}"
    if [[ ! -s "$crt_cache" ]]; then
        curl "${CURL_OPTS[@]}" "https://crt.sh/?q=%25.$target" > "$crt_cache"
    fi
    sed -e 's/<[^>]*>//g' < "$crt_cache" | \
        grep -oP "([a-zA-Z0-9_-]+\\.$target)" | grep "\.$target$" | sort -u >> "$folder/final.txt"
    log "${COLOR_RED}Subdomains found:${COLOR_RESET} $(wc -l < "$folder/final.txt")"

    set_phase "amass: brute/active"
    log "${COLOR_GREEN}[+] Enumerating subdomains with amass (brute+active)...${COLOR_RESET}"
    amass enum -silent -brute -active -timeout 10 -max-dns-queries 10000 -o "$folder/amass.txt" -d "$target" > /dev/null 2>&1

    set_phase "ffuf: bruteforcing subdomains"
    log "${COLOR_GREEN}[+] Bruteforcing subdomains with ffuf...${COLOR_RESET}"
    ffuf -s -w /opt/Automatic/dic.txt -u https://FUZZ.$target -H "Host: FUZZ.$target" -mc 200,301,302 -fs 0 -t 50 -o "$folder/ffuf_found.txt" -of csv > /dev/null

    if [ -s "$folder/ffuf_found.txt" ]; then
        while IFS= read -r raw; do
            [[ -z "$raw" ]] && continue
            h="${raw#http://}"
            h="${h#https://}"
            h="${h%%/*}"
            h="${h%%:*}"
            host_in_scope "$h" "$target" && echo "$h"
        done < <(awk -F',' 'NR>1{print $2}' "$folder/ffuf_found.txt") >> "$folder/final.txt"
    fi

    set_phase "dnsx: brute DNS"
    log "${COLOR_GREEN}[+] Bruteforcing DNS with dnsx...${COLOR_RESET}"
    dnsx -silent -wordlist /opt/Automatic/dic.txt -domain "$target" -a -resp -o "$folder/dnsx_found.txt" > /dev/null

    if [ -s "$folder/dnsx_found.txt" ]; then
        while IFS= read -r h; do
            [[ -z "$h" ]] && continue
            host_in_scope "$h" "$target" && echo "$h"
        done < <(awk '{print $1}' "$folder/dnsx_found.txt") >> "$folder/final.txt"
    fi

    if [[ -s "$folder/amass.txt" ]]; then
        cat "$folder/amass.txt" | grep "\.$target$" >> "$folder/final.txt"
    fi
    log "${COLOR_RED}Subdomains found:${COLOR_RESET} $(wc -l < "$folder/final.txt")"

    # Dominio apex (ej. usgeo.gov): los grep tipo \.$target$ solo dejan subdominios *.target
    echo "$target" >> "$folder/final.txt"

    sort -u "$folder/final.txt" -o "$folder/final.txt"
    filter_exclusions "$folder/final.txt"
    sort -u "$folder/final.txt" -o "$folder/final.txt"
    subs_count=$(wc -l < "$folder/final.txt")

    set_phase "httpx: checking live"
    log "${COLOR_GREEN}[+] Checking live subdomains with httpx...${COLOR_RESET}"
    # Listas enormes: httpx puede tardar horas; sin línea Time: (ticker suprimido); al terminar se muestra duración + hosts.
    if [[ "$subs_count" -gt 8000 && "$silent" != "true" ]]; then
        warn "${COLOR_YELLOW}[!] Muchos subdominios ($subs_count): httpx tardará bastante (varios puertos por host). No es un cuelgue; al terminar verás tiempo y cantidad de hosts vivos. Considera -only o acotar scope.${COLOR_RESET}"
    fi
    # live.txt = única lista de subdominios vivos; waymore, nuclei y el resto trabajan siempre desde live.txt
    # -fd: filtra respuestas casi duplicadas en httpx; sort -u sigue deduplicando live.txt en disco.
    # Durante httpx/liveInfo/screenshots/waymore: sin Time: en pantalla; el reloj interno del ticker sigue (START_TS).
    httpx_live_start=$(date +%s)
    ticker_suppress_on
    if [[ "$silent" == "true" ]]; then
        httpx -p 80,443,8080,8443,8000,3000,9000 -fd -silent < "$folder/final.txt" > "$folder/live.txt" 2>/dev/null
    else
        httpx -p 80,443,8080,8443,8000,3000,9000 -fd < "$folder/final.txt" | tee "$folder/live.txt"
    fi
    sort -u "$folder/live.txt" -o "$folder/live.txt"
    filter_exclusions "$folder/live.txt"
    live_count=$(wc -l < "$folder/live.txt")
    if [[ "$silent" != "true" ]]; then
        log "${COLOR_GREEN}[✓] httpx live hosts ${COLOR_CYAN}($(format_elapsed "$httpx_live_start"))${COLOR_RESET} — ${COLOR_CYAN}${live_count}${COLOR_RESET} hosts"
    fi
    if [[ "$live_count" -eq 0 && "$subs_count" -gt 0 ]]; then
        log "${COLOR_YELLOW}[!] httpx: 0 hosts vivos con puertos probados; waymore/nuclei no tendrán objetivos (red, DNS, firewall o sin HTTP/S en 80/443/…)${COLOR_RESET}"
    fi

    # liveInfo = mismas URLs que live.txt pero con columnas extra (status, title, etc.)
    # -silent: sin banner duplicado (httpx ya se lanzó arriba); sigue saliendo la tabla a pantalla/archivo.
    if [[ "$silent" == "true" ]]; then
        httpx --status-code --content-length -title -fr -fd -silent \
            -p 80,443,8080,8443,8000,3000,9000 < "$folder/live.txt" > "$folder/liveInfo.txt" 2>/dev/null
    else
        httpx --status-code --content-length -title -fr -fd -silent \
            -p 80,443,8080,8443,8000,3000,9000 < "$folder/live.txt" | tee "$folder/liveInfo.txt"
    fi
    # No filtrar liveInfo para mantener la misma cantidad de líneas que live.txt
    [[ "$silent" != "true" ]] && log ""

    # Screenshots (headless) desde live.txt — tras liveInfo, antes de waymore.
    # -sid = segundos de espera antes de capturar (página estable); -st = timeout; -t bajo = menos Chrome en paralelo
    set_phase "httpx: screenshots"
    log "${COLOR_GREEN}[+] Taking screenshots from live.txt (httpx -ss)...${COLOR_RESET}"
    mkdir -p "$folder/screenshots"
    if [[ -s "$folder/live.txt" ]]; then
        if [[ "$silent" == "true" ]]; then
            httpx -ss -t 10 -system-chrome -srd "$folder/screenshots" -fd -silent \
                -p 80,443,8080,8443,8000,3000,9000 \
                -sid 3 -st 15 \
                < "$folder/live.txt" > /dev/null 2>/dev/null
        else
            # Sin tercer banner ni lista de URLs: solo capturas en disco
            httpx -ss -t 10 -system-chrome -srd "$folder/screenshots" -fd -silent \
                -p 80,443,8080,8443,8000,3000,9000 \
                -sid 3 -st 15 \
                < "$folder/live.txt" > /dev/null
        fi
    else
        log "${COLOR_YELLOW}[!] live.txt vacío — sin screenshots${COLOR_RESET}"
    fi
    [[ "$silent" != "true" ]] && log ""

    rm -f "$folder/final.txt"
    # Enumeración ya consolidada en live.txt / liveInfo.txt: borrar intermedios
    rm -f "$folder/ffuf_found.txt" "$folder/dnsx_found.txt" "$folder/amass.txt"

    if [[ "$mode" == "subs" ]]; then
        ticker_suppress_off
        # Print summary before returning
        log ""
        log "${COLOR_CYAN}[*] ─── Summary for $target ───${COLOR_RESET}"
        log "${COLOR_CYAN}    Subdomains found : ${COLOR_GREEN}${subs_count}${COLOR_RESET}"
        log "${COLOR_CYAN}    Live hosts       : ${COLOR_GREEN}${live_count}${COLOR_RESET}"
        log "${COLOR_CYAN}    Output folder    : ${COLOR_GREEN}${folder}/${COLOR_RESET}"
        log ""
        return 0
    fi

    set_phase "waymore: collecting URLs"
    # Sin Time: durante waymore (ticker sigue suprimido desde httpx); al terminar: duración + URLs.
    ticker_suppress_on
    log "${COLOR_GREEN}[+] Gathering URLs with waymore (Wayback, Common Crawl, etc.)...${COLOR_RESET}"
    sed -e 's|^[^:]*://||' -e 's|/.*||' -e 's|:[0-9]*$||' "$folder/live.txt" | sort -u > "$folder/waymore_hosts.txt"
    local waymore_filter_re='\.(jpg|png|svg|gif|woff|woff2|ico)$'
    # Waymore con archivo de varios dominios SOBRESCRIBE -oU en cada dominio (solo queda el último). Ejecutamos 1 dominio por vez y concatenamos.
    [[ -n "$folder" ]] && : > "$folder/allurls.txt"
    local waymore_start waymore_idx=0 waymore_total
    waymore_total=$(wc -l < "$folder/waymore_hosts.txt")
    waymore_start=$(date +%s)
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        waymore_idx=$((waymore_idx + 1))
        if [[ "$silent" != "true" ]]; then
            set_phase "waymore: [$waymore_idx/$waymore_total] $domain"
        fi
        local tmpurls="$folder/waymore_${waymore_idx}.tmp"
        "${TIMEOUT_CMD[@]}" waymore -i "$domain" -mode U -oU "$tmpurls" 2>/dev/null
        if [[ -s "$tmpurls" ]]; then
            cat "$tmpurls" >> "$folder/allurls.txt"
        fi
        rm -f "$tmpurls"
        [[ "$INTERRUPTED" -eq 1 ]] && break
    done < "$folder/waymore_hosts.txt"
    rm -f "$folder/waymore_hosts.txt"
    if [[ -s "$folder/allurls.txt" ]]; then
        sort -u "$folder/allurls.txt" -o "$folder/allurls.txt"
        grep -E -iv "$waymore_filter_re" "$folder/allurls.txt" > "$folder/allurls.tmp" && mv "$folder/allurls.tmp" "$folder/allurls.txt"
    fi
    rm -f "$folder/allurls.tmp"
    ticker_suppress_off
    if [[ "$silent" != "true" ]]; then
        log "${COLOR_GREEN}[✓] waymore finished ${COLOR_CYAN}($(format_elapsed "$waymore_start"))${COLOR_RESET} — ${COLOR_CYAN}$(wc -l < "$folder/allurls.txt")${COLOR_RESET} URLs"
        [[ "$mode" == "full" ]] && log ""
    fi

    if [[ ! -s "$folder/allurls.txt" ]]; then
        [[ -n "$folder" ]] && : > "$folder/allurls.txt"
    fi

    urls_count=$(wc -l < "$folder/allurls.txt")

    if [[ "$mode" == "recon" ]]; then
        remove_empty_vuln_outputs "$folder"
        log ""
        log "${COLOR_CYAN}[*] ─── Summary for $target ───${COLOR_RESET}"
        log "${COLOR_CYAN}    Subdomains found : ${COLOR_GREEN}${subs_count}${COLOR_RESET}"
        log "${COLOR_CYAN}    Live hosts       : ${COLOR_GREEN}${live_count}${COLOR_RESET}"
        log "${COLOR_CYAN}    URLs collected   : ${COLOR_GREEN}${urls_count}${COLOR_RESET}"
        log "${COLOR_CYAN}    Output folder    : ${COLOR_GREEN}${folder}/${COLOR_RESET}"
        log ""
        return 0
    fi

    if [[ "$mode" == "full" ]]; then
        set_phase "nuclei/xss/cors"
        if [[ ! -s "$folder/live.txt" ]]; then
            log "${COLOR_YELLOW}[!] Sin hosts en live.txt — nuclei / XSS / CORS omitidos (nada que escanear)${COLOR_RESET}"
            nuclei_count=0
            xss_count=0
            cors_count=0
            rm -f "$folder/nuclei.txt" "$folder/xss_vulnerables.txt" "$folder/cors.txt"
        else
            local nuclei_start xss_start cors_start

            log "${COLOR_GREEN}[+] Running nuclei scans:${COLOR_RESET}"
            nuclei_start=$(date +%s)
            set_phase "nuclei"
            ticker_suppress_on
            if [[ "$silent" == "true" ]]; then
                "${TIMEOUT_CMD[@]}" nuclei -silent -rl 150 -l "$folder/live.txt" -es info | tee "$folder/nuclei.txt" > /dev/null
            else
                "${TIMEOUT_CMD[@]}" nuclei -rl 150 -l "$folder/live.txt" -es info | tee "$folder/nuclei.txt"
            fi
            nuclei_count=$(wc -l < "$folder/nuclei.txt" 2>/dev/null | tr -d ' ' || echo 0)
            ticker_suppress_off
            log "${COLOR_GREEN}[✓] Nuclei done ${COLOR_CYAN}($(format_elapsed "$nuclei_start"))${COLOR_RESET} — ${COLOR_CYAN}${nuclei_count}${COLOR_RESET} findings"

            # XSS detection via freq (more reliable than raw curl grep)
            log "${COLOR_GREEN}[+] Running XSS checks...${COLOR_RESET}"
            xss_start=$(date +%s)
            set_phase "XSS (freq)"
            # uro/qsreplace/freq usan el parser de URLs de Go: líneas basura (Wayback con JSP/%) → stderr; 2>/dev/null evita ruido
            if [[ "$silent" == "true" ]]; then
                cat "$folder/allurls.txt" | grep "=" | grep -v "^$" | uro 2>/dev/null | \
                    qsreplace '"><img src=x onerror=alert(1);>' 2>/dev/null | freq 2>/dev/null | \
                    grep -i "vulnerable" | grep -vi "not vulnerable" | \
                    tee "$folder/xss_vulnerables.txt" > /dev/null
            else
                cat "$folder/allurls.txt" | grep "=" | grep -v "^$" | uro 2>/dev/null | \
                    qsreplace '"><img src=x onerror=alert(1);>' 2>/dev/null | freq 2>/dev/null | \
                    grep -i "vulnerable" | grep -vi "not vulnerable" | \
                    tee "$folder/xss_vulnerables.txt"
            fi
            xss_count=$(wc -l < "$folder/xss_vulnerables.txt" 2>/dev/null | tr -d ' ' || echo 0)
            log "${COLOR_GREEN}[✓] XSS checks done ${COLOR_CYAN}($(format_elapsed "$xss_start"))${COLOR_RESET} — ${COLOR_CYAN}${xss_count}${COLOR_RESET} candidates"

            # CORS detection — checks for reflected Origin in Access-Control-Allow-Origin header
            log "${COLOR_GREEN}[+] Running CORS checks.${COLOR_RESET}"
            cors_start=$(date +%s)
            set_phase "CORS"
            ticker_suppress_on
            if [[ "$silent" == "true" ]]; then
                httpx -threads 300 -follow-redirects -silent < "$folder/live.txt" | \
                    rush -j200 'r=$(curl -m5 -s -I -H "Origin: evil.com" {}); echo "$r" | grep -qi "Access-Control-Allow-Origin: evil.com" && echo "[VUL TO CORS] {}"' \
                    2>/dev/null | tee "$folder/cors.txt" > /dev/null
            else
                httpx -threads 300 -follow-redirects -silent < "$folder/live.txt" | \
                    rush -j200 'r=$(curl -m5 -s -I -H "Origin: evil.com" {}); echo "$r" | grep -qi "Access-Control-Allow-Origin: evil.com" && echo "[VUL TO CORS] {}"' \
                    2>/dev/null | tee "$folder/cors.txt"
            fi
            # No ticker_suppress_off aquí: si no, el ticker vuelve a pintar "Time: … | CORS" hasta el final del script
            cors_count=$(wc -l < "$folder/cors.txt" 2>/dev/null | tr -d ' ' || echo 0)
            log "${COLOR_GREEN}[✓] CORS checks done ${COLOR_CYAN}($(format_elapsed "$cors_start"))${COLOR_RESET} — ${COLOR_CYAN}${cors_count}${COLOR_RESET} findings"
            set_phase "Summary"
        fi
        remove_empty_vuln_outputs "$folder"
    fi

    # Cleanup temp files (ffuf/dnsx/amass/waymore_hosts ya borrados antes)
    rm -f "$folder/allurls.tmp" "$folder/waymore_stderr.log"
    remove_empty_vuln_outputs "$folder"

    set_phase "Finished"
    ticker_suppress_on
    [[ "$silent" != "true" ]] && log ""
    log "${COLOR_GREEN}[+] Scan complete for $target. Results saved in $folder/${COLOR_RESET}"

    # Final summary
    log ""
    log "${COLOR_CYAN}[*] ─── Summary for $target ───${COLOR_RESET}"
    log "${COLOR_CYAN}    Subdomains found  : ${COLOR_GREEN}${subs_count}${COLOR_RESET}"
    log "${COLOR_CYAN}    Live hosts        : ${COLOR_GREEN}${live_count}${COLOR_RESET}"
    log "${COLOR_CYAN}    URLs collected    : ${COLOR_GREEN}${urls_count}${COLOR_RESET}"
    case "$mode" in
        full)
            log "${COLOR_CYAN}    Nuclei findings   : ${COLOR_GREEN}${nuclei_count}${COLOR_RESET}"
            log "${COLOR_CYAN}    XSS candidates    : ${COLOR_GREEN}${xss_count}${COLOR_RESET}"
            log "${COLOR_CYAN}    CORS vulns        : ${COLOR_GREEN}${cors_count}${COLOR_RESET}"
            ;;
    esac
    log "${COLOR_CYAN}    Output folder     : ${COLOR_GREEN}${folder}/${COLOR_RESET}"
    if [[ -n "$LOG_FILE" ]]; then
        log "${COLOR_CYAN}    Log file          : ${COLOR_GREEN}${LOG_FILE}${COLOR_RESET}"
    fi
    log ""
}

normalize_excludes

run_target() {
    local target="$1"
    local recon_seed="$output/_recon_${target}_all.txt"
    local recon_json
    local targets_file="$output/_recon_${target}_targets.txt"
    local seed_target
    log "${COLOR_CYAN}[~] Starting Automatic for $target${COLOR_RESET}"
    set_phase "Automatic for $target"
    # Ruta fija: recon_inverso escribe recon_<target>.json (no usar $(run_recon) — capturaba todo el print de Python)
    local recon_json_path="$output/recon_${target}.json"
    run_recon "$target" "$recon_seed"
    get_recon_targets "$target" "$recon_json_path" "$targets_file"
    rm -f "$recon_json_path"
    filter_exclusions "$targets_file"
    while IFS= read -r recon_target; do
        seed_target="$output/_recon_${target}_${recon_target}_seed.txt"
        seed_for_target "$recon_seed" "$recon_target" "$seed_target"
        filter_exclusions "$seed_target"
        scan_url "$recon_target" "$seed_target"
        rm -f "$seed_target"
    done < "$targets_file"
    rm -f "$recon_seed" "$targets_file"
}

if [[ -n "$url_list" ]]; then
    if [[ "$max_jobs" -le 1 ]]; then
        while IFS= read -r target; do
            run_target "$target"
        done < "$url_list"
    else
        running=0
        while IFS= read -r target; do
            run_target "$target" &
            running=$((running + 1))
            if [[ "$running" -ge "$max_jobs" ]]; then
                wait -n
                running=$((running - 1))
            fi
        done < "$url_list"
        wait
    fi
else
    run_target "$url"
fi

ticker_stop

# Mensaje final con printf y %%s para LOG_FILE (rutas raras no rompen el quoting)
if [[ "$create_log" == "true" && -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
    printf '%b[*] Scan finished. Log saved to: %b%s%b\n' "$COLOR_CYAN" "$COLOR_GREEN" "$LOG_FILE" "$COLOR_RESET"
fi
