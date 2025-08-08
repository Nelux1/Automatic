<a href='https://cafecito.app/nelux' rel='noopener' target='_blank'><img srcset='https://cdn.cafecito.app/imgs/buttons/button_6.png 1x, https://cdn.cafecito.app/imgs/buttons/button_6_2x.png 2x, https://cdn.cafecito.app/imgs/buttons/button_6_3.75x.png 3.75x' src='https://cdn.cafecito.app/imgs/buttons/button_6.png' alt='Invitame un café en cafecito.app' /></a>

# Automatic.sh

Automated Reconnaissance and Vulnerability Scanning Tool

Overview
This Bash script automates subdomain enumeration, reconnaissance, and vulnerability scanning.
It combines several well-known tools into a single workflow, allowing you to scan a single target or a list of targets efficiently.

It supports three main modes:

Subdomain enumeration only

Reconnaissance (subdomains + URL gathering)

Full scan (including vulnerability checks)

📦 Features
Subdomain Enumeration via:

assetfinder

subfinder

RapidDNS & crt.sh scraping

amass (brute-force & active)

ffuf DNS bruteforce

dnsx enumeration

Live Host Detection using httpx

URL Gathering with gau

Vulnerability Scanning with:

nuclei

Basic XSS detection

Basic CORS misconfiguration checks

Output management – results organized in separate folders per target.

⚙️ Requirements
Make sure you have the following tools installed and accessible in $PATH:

assetfinder

subfinder

amass

ffuf

dnsx

httpx

gau

nuclei

curl, grep, awk, sed, sort

A wordlist (named dic.txt in script)

📖 Usage
bash
Copiar
Editar
./scanner.sh [options]
Options
Option	Description
-h	Show help message
-a	Full scan (recon + vulnerability scanning)
-l file	Use a file containing a list of URLs
-u url	Scan a single URL
-o name	Specify output folder name (default: scan_results)
-s	Subdomain enumeration only
-r	Recon only (subdomains + gau, no vulnerability scans)

🖥️ Examples
Scan a single target (full mode)
bash
Copiar
Editar
./automatic.sh -a -u example.com
Scan multiple targets from a file (recon mode)
bash
Copiar
Editar
./automatic.sh -r -l targets.txt
Subdomain enumeration only
bash
Copiar
Editar
./automatic.sh -s -u example.com
Save results in a custom folder
bash
Copiar
Editar
./automatic.sh -a -u example.com -o myresults
📂 Output Structure
Each scan creates a folder:

bash
Copiar
Editar
scan_results/
└── example.com/
    ├── live.txt              # Live subdomains
    ├── liveInfo.txt          # Detailed HTTP info
    ├── allurls.txt           # URLs from gau
    ├── nuclei.txt            # Nuclei scan results
    ├── xss_vulnerables.txt   # XSS findings
    ├── cors.txt              # CORS issues
⚠️ Disclaimer
This tool is for educational and authorized testing purposes only.
Do NOT use it against systems you do not own or have explicit permission to test.

If you want, I can also prepare a diagram showing the workflow of this script from subdomain enumeration to vulnerability scanning, so your students or team can understand the process visually. That could make the README even more engaging.
