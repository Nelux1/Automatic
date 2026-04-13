# AutomaticRec — Automated Reverse Recon & Vulnerability Scanner

> Automated tool for reverse reconnaissance, subdomain enumeration, and vulnerability scanning. Designed for bug bounty hunters and penetration testers.

<a href='https://cafecito.app/nelux' rel='noopener' target='_blank'><img srcset='https://cdn.cafecito.app/imgs/buttons/button_6.png 1x, https://cdn.cafecito.app/imgs/buttons/button_6_2x.png 2x, https://cdn.cafecito.app/imgs/buttons/button_6_3.75x.png 3.75x' src='https://cdn.cafecito.app/imgs/buttons/button_6.png' alt='Invitame un café en cafecito.app' /></a>

---

## How it works

`AutomaticRec.sh` first runs `recon_inverso.py` to map the full infrastructure of a company (ASNs, IP ranges, related domains, and acquisitions), then runs the full subdomain enumeration and scanning pipeline against every discovered domain.

```
AutomaticRec.sh -u target.com
        │
        ├─ [1] recon_inverso.py        → Finds all company-owned domains (incl. acquisitions)
        │       Uses: ASN lookup, reverse DNS, WHOIS ownership verification
        │
        └─ [2] For each discovered domain:
                ├─ assetfinder, subfinder, RapidDNS, crt.sh, amass, ffuf, dnsx
                ├─ httpx      → live hosts
                ├─ waymore   → URL collection (Wayback, Common Crawl, etc.) → `allurls.txt`
                └─ nuclei + XSS + CORS checks  (only with -a)
```

*[Katana](https://github.com/projectdiscovery/katana) headless crawling is not built in — run it separately against `live.txt` if you need dynamic URLs beyond waymore.)*

The key differentiator: domains discovered via **reverse DNS are accepted only if WHOIS confirms the same registrant**, so acquisitions are included but unrelated shared-hosting neighbors are not.

---

## Requirements

### System
- Bash 4.3+
- Python 3.8+
- Go (for installing Go-based tools)
### Python dependencies
```
pip3 install -r requirements.txt
```

### External tools (must be in PATH)

| Tool | Install |
|------|---------|
| `assetfinder` | `go install github.com/tomnomnom/assetfinder@latest` |
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `chaos` | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| `amass` | `go install github.com/owasp-amass/amass/v4/...@latest` |
| `ffuf` | `go install github.com/ffuf/ffuf@latest` |
| `dnsx` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `waymore` | `pip3 install waymore` |
| `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `qsreplace` | `go install github.com/tomnomnom/qsreplace@latest` |
| `uro` | `pip3 install uro` |
| `freq` | `pip3 install freq` |
| `rush` | `cargo install rush-cli` |
| `whois`, `dig` | `apt install whois dnsutils` |

### Wordlist
The script expects a wordlist at `/opt/Automatic/dic.txt`.
You can change this path inside `AutomaticRec.sh` if needed.

### Optional API key
To enable Chaos, set your API key:
```
export CHAOS_KEY="your_key_here"
```
You can also set it in `AutomaticRec.conf` (loaded automatically at runtime):
```
CHAOS_KEY="your_key_here"
```

---

## Quick install

```bash
sudo bash Install_requirements.sh
```

This installs all Go tools, Python dependencies, and system packages automatically.

---

## Usage

```
./AutomaticRec.sh [options]
```

### Basic flags

| Flag | Description |
|------|-------------|
| `-u domain.com` | Single target domain |
| `-l file.txt` | File with list of targets (one per line) |
| `-a` | Full scan: subdomains + waymore + nuclei + XSS + CORS |
| `-r` | Recon only: subdomains + waymore → `allurls.txt`, no vuln scanning |
| `-s` | Subdomain enumeration only |
| `-o folder` | Output folder name (default: `scan_results`) |
| `-only` | Scan only the specified domain, skip recon expansion |
| `-x a.com,sub.b.com` | Exclude specific domains/subdomains (CSV) |
| `--silent` | Suppress screen output |
| `--log` | Write `automaticrec.log` under `-o` (optional) |
| `--timeout N` | Global timeout in seconds for tools without one |
| `-j N` | Parallel targets (only with `-l`) |
| `--refresh-cache` | Ignore RapidDNS/crt.sh local cache |
| `-h` | Show help |

### Pipeline by mode (`-s` / `-r` / `-a`)

Per target, the script always runs **reverse recon** (unless `-only`), then **subdomain enumeration** (assetfinder, subfinder, chaos if configured, RapidDNS, crt.sh, amass, ffuf, dnsx), then **httpx** (`live.txt`, `liveInfo.txt`) — **except** in `-s` mode, which stops after that.

| Stage | `-s` (subs only) | `-r` (recon) | `-a` (full) |
|-------|:----------------:|:------------:|:-----------:|
| Subdomains + httpx | ✅ | ✅ | ✅ |
| **waymore** → `allurls.txt` | ❌ | ✅ | ✅ |
| **nuclei** (on `live.txt`) | ❌ | ❌ | ✅ |
| **XSS** (uro / qsreplace / freq on `allurls.txt`) | ❌ | ❌ | ✅ |
| **CORS** (httpx + rush + curl on `live.txt`) | ❌ | ❌ | ✅ |

Use **`-r`** for passive/historical URLs (waymore) without vuln scans; use **`-a`** for the complete pipeline. Prefer always passing **`-r`** or **`-a`** so behavior is explicit (if neither is set, waymore still runs but vuln scans do not).

### Reverse recon tuning flags

| Flag | Description |
|------|-------------|
| `--recon-max-ips N` | Max IPs to enumerate from ASN (default: 1000) |
| `--recon-max-ips-reverse N` | Max IPs for reverse DNS lookups (default: 200) |
| `--recon-max-domains-sub N` | Max domains for subdomain search (default: 10) |
| `--recon-max-ips-ec2 N` | Max IPs for EC2 detection (default: 100) |
| `--recon-threads N` | Thread count for recon_inverso (default: 20) |
| `--recon-aws-cache-ttl N` | AWS ranges cache TTL in seconds (default: 3600) |
| `--recon-skip-ownership-check` | Skip WHOIS ownership verification (faster, less precise) |

---

## Examples

```bash
# Full scan on a single target
./AutomaticRec.sh -u example.com -a

# Subdomain enumeration only
./AutomaticRec.sh -u example.com -s

# Recon + waymore (allurls.txt), no vuln scans
./AutomaticRec.sh -u example.com -r

# Scan only the specified domain (no acquisition expansion)
./AutomaticRec.sh -u example.com -a -only

# Exclude specific domains from scope
./AutomaticRec.sh -u example.com -a -x staging.example.com,legacy.example.com

# Multiple targets in parallel
./AutomaticRec.sh -l targets.txt -a -j 3

# Full scan, silent, with recon tuning
./AutomaticRec.sh -u example.com -a --silent \
  --recon-max-ips 500 \
  --recon-max-domains-sub 5

# Skip WHOIS checks (faster, may include more noise)
./AutomaticRec.sh -u example.com -a --recon-skip-ownership-check
```

---

## Output structure

```
scan_results/
└── example.com/
    ├── live.txt              # Live subdomains (httpx)
    ├── liveInfo.txt          # Live host details (status, title, size)
    ├── allurls.txt           # URLs from waymore only (deduped, extension-filtered); optional Katana crawl is manual
    ├── nuclei.txt            # Nuclei findings (only with -a, only if non-empty)
    ├── xss_vulnerables.txt   # XSS candidates (only with -a, only if non-empty)
    └── cors.txt              # CORS issues (only with -a, only if non-empty)
```

Intermediate reverse-recon files under `scan_results/` are removed after use (no persistent `recon_*.json` by default). `automaticrec.log` is the full execution log when logging is enabled.

---

## Domain scope explained

By default, `AutomaticRec.sh` does **full company scope**:
- Discovers all domains owned by the company via ASN + reverse DNS
- Verifies ownership with WHOIS (filters out shared hosting neighbors)
- Includes subsidiaries and acquisitions (different domain names, same registrant)

Use `-only` to restrict scope to **only the domain you specify**, ignoring any other discovered domains.

Use `-x` to **explicitly exclude** specific domains or subdomains from any mode.

---

## recon_inverso.py (standalone)

You can also run the reverse recon module independently:

```bash
python3 recon_inverso.py -u example.com -o output.txt -v
```

| Flag | Description |
|------|-------------|
| `-u` | Target domain or company name |
| `-o file` | Output file for domains/subdomains found |
| `-v` | Verbose output |
| `-ra` | Use random User-Agent |
| `-t N` | Thread count (default: 20) |
| `--max-ips N` | Max IPs from ASN |
| `--max-ips-reverse N` | Max IPs for reverse DNS |
| `--max-domains-sub N` | Max domains for subdomain search |
| `--skip-ownership-check` | Skip WHOIS verification |
| `--aws-cache-ttl N` | AWS ranges cache TTL |

Results are saved as `recon_<domain>.json` with ASNs, IPs, domains, subdomains, and EC2 instances found.

---

## Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**.
Do not use it against systems you do not own or have explicit written permission to test.
The authors are not responsible for any misuse or damage caused by this tool.
