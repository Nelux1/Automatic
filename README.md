<a href='https://cafecito.app/nelux' rel='noopener' target='_blank'><img srcset='https://cdn.cafecito.app/imgs/buttons/button_6.png 1x, https://cdn.cafecito.app/imgs/buttons/button_6_2x.png 2x, https://cdn.cafecito.app/imgs/buttons/button_6_3.75x.png 3.75x' src='https://cdn.cafecito.app/imgs/buttons/button_6.png' alt='Invitame un café en cafecito.app' /></a>

# Automatic.sh

Automated Reconnaissance and Vulnerability Scanning Tool

This script automates the process of reconnaissance, subdomain enumeration, and vulnerability scanning for a given domain. It leverages multiple tools and online services to gather detailed information about the target.

Features

Subdomain Enumeration using Assetfinder, Subfinder, RapidDNS, and crt.sh.

Live Subdomain Checking with Httpx.

URL Discovery using GAU (Get All URLs).

Vulnerability Scanning with Nuclei (XSS, CORS, and other vulnerabilities).

Installation

Ensure you have the following tools installed before running the script:
      sudo apt update && sudo apt install -y assetfinder subfinder httpx gau nuclei curl

Or install via Go:
      go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
      go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
      go install -v github.com/lc/gau/v2/cmd/gau@latest
      go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   
Usage
Run the script with different options:

        ./Automatic.sh -u example.com

Options
            Usage: ./recon_tool.sh [-h] [-a] [-l file] [-u url] [-o output] [-s] [-r]
      
         Options:
           -h         Show this help message
           -a         Perform full scan including vulnerability scanning
           -l file    Use a file containing a list of URLs
           -u url     Scan a single URL
           -o output  Specify output folder name
           -s         Perform only subdomain enumeration
           -r         Perform reconnaissance (subdomains + gau), but no vulnerability scans   

Examples

1. Scan a Single Domain

          ./Automatic.sh -u example.com

2. Scan Multiple Domains from a File

         ./Automatic.sh -l targets.txt

3. Perform Only Subdomain Enumeration

         ./Automatic.sh -s -u example.com

4. Perform Full Reconnaissance Without Vulnerability Scanning

         ./Automatic.sh -r -u example.com

5. Perform Full Scan (Subdomains + Vulnerability Scanning)

         ./Automatic.sh -a -u example.com

Output

The results will be saved in a directory named scan_results/ by default, unless specified otherwise using -o.

Example Output Structure:

     scan_results/
         └── example.com/
             ├── final.txt         # All found subdomains
             ├── live.txt          # Live subdomains
             ├── urls.txt          # URLs collected with gau
             ├── nuclei.txt        # Nuclei scan results
             ├── xss_vulnerable.txt # XSS vulnerabilities detected
             ├── cors.txt          # CORS misconfigurations detected
