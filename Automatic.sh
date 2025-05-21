#!/bin/bash

banner="

     e                 d8                                      d8   ,e,
    d8b     888  888 _d88__  e88~-_  888-~88e-~88e   /~~~8e  _d88__      e88~~
   /Y88b    888  888  888   d888   i 888  888  888       88b  888   888 d888
  /  Y88b   888  888  888   8888   | 888  888  888  e88~-888  888   888 8888
 /____Y88b  888  888  888   Y888   | 888  888  888 C888  888  888   888 Y888
/      Y88b  88_-888   88_/   88_-~  888  888  888   88_-888   88_/ 888   88__/
"

echo -e "$banner"

help_message() {
    echo "Usage: $0 [-h] [-a] [-l file] [-u url] [-o output] [-s] [-r]"
    echo ""
    echo "Options:"
    echo "  -h         Show this help message"
    echo "  -a         Perform full scan including vulnerability scanning"
    echo "  -l file    Use a file containing a list of URLs"
    echo "  -u url     Scan a single URL"
    echo "  -o output  Specify output folder name"
    echo "  -s         Perform only subdomain enumeration"
    echo "  -r         Perform reconnaissance (subdomains + gau), but no vulnerability scans"
    exit 1
}

# Default values
mode=""
output="scan_results"

while getopts "hal:u:o:sr" opt; do
    case $opt in
        h) help_message ;;
        a) mode="full" ;;
        l) url_list="$OPTARG" ;;
        u) url="$OPTARG" ;;
        o) output="$OPTARG" ;;
        s) mode="subs" ;;
        r) mode="recon" ;;
        \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    esac
done

if [[ -z "$url" && -z "$url_list" ]]; then
    echo "Error: You must specify either -u (URL) or -l (list file)"
    exit 1
fi

scan_url() {
    local target=$1
    local folder="$output/$target"

    mkdir -p "$folder"

    echo -e "\e[32m[+] Enumerating subdomains with assetfinder...\e[0m"
    assetfinder "$target" | grep "$target" >> "$folder/final.txt"
    echo -e "\e[31mSubdomains found:\e[0m $(wc -l < "$folder/final.txt")"

    echo -e "\e[32m[+] Enumerating subdomains with subfinder...\e[0m"
    subfinder -d "$target" -silent >> "$folder/final.txt"
    echo -e "\e[31mSubdomains found:\e[0m $(wc -l < "$folder/final.txt")"

    echo -e "\e[32m[+] Enumerating subdomains with RapidDNS...\e[0m"
    curl -s "https://rapiddns.io/subdomain/$target?full=1" | sed -e 's/<[^>]*>//g' | \
        grep -oP "([a-zA-Z0-9_-]+\\.$target)" | sort -u | tee -a "$folder/final.txt"
    echo -e "\e[31mSubdomains found:\e[0m $(wc -l < "$folder/final.txt")"

    echo -e "\e[32m[+] Enumerating subdomains with crt.sh...\e[0m"
    curl -s "https://crt.sh/?q=%25.$target" | sed -e 's/<[^>]*>//g' | \
        grep -oP "([a-zA-Z0-9_-]+\\.$target)" | sort -u | tee -a "$folder/final.txt"
    echo -e "\e[31mSubdomains found:\e[0m $(wc -l < "$folder/final.txt")"

    echo -e "\e[32m[+] Checking lives subdomains with httpx...\e[0m"
    cat "$folder/final.txt" | httpx -p  80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 > "$folder/live.txt"

    cat "$folder/final.txt" | httpx --status-code --content-length -title -fr -verbose -p  80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 >> "$folder/liveInfo.txt"

    cat "$folder/live.txt" | httpx -ss -t 20 -system-chrome

    rm -f "$folder/final.txt"

    if [[ "$mode" == "subs" ]]; then
        exit 0
    fi

    echo -e "\e[32m[+] Gathering URLs with gau...\e[0m"
    cat "$folder/live.txt" | gau --subs | grep -E -iv "\.(jpg|png|svg|gif|woff|woff2|ico)" | tee -a "$folder/allurls.txt"

    if [[ "$mode" == "recon" ]]; then
        exit 0
    fi

    if [[ "$mode" == "full" ]]; then
        echo -e "\e[32m[+] Running nuclei scans, xss and cors...\e[0m"
        nuclei -l "$folder/live.txt" -t ~/nuclei-templates -es info | tee -a "$folder/nuclei.txt"

        cat "$folder/allurls.txt" | tee -a "$folder/archivo.txt" | grep "=" | \
            egrep -iv ".(jpg|peg|gif|css|tif|tiff|png|woff|woff2|ico|pdf|svg|txt|js)" | \
            qsreplace '"><script>confirm(1)</script>' | tee -a "$folder/arch.json" && \
            cat "$folder/arch.json" | while read host; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;031mVulnerable\n" | tee -a "$folder/xss_vulnerables.txt"; done

        rm -f "$folder/archivo.txt"
        rm -f "$folder/arch.json"

        cat "$folder/allurls.txt" | grep "=" | grep -v "^$" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | grep -i "vulnerable" | tee -a "$folder/xss_vulnerables.txt"

        cat "$folder/live.txt" | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H "Origin:evil.com" {} | [[ $(grep -c "evil.com") -gt 0 ]] && printf "\n\033[0;32m[VUL TO CORS] - {}\e[m"' 2>/dev/null | tee -a "$folder/cors.txt"
    fi

    echo -e "\e[32m[+] Scan complete for $target. Results saved in $folder/\e[0m"
}

if [[ -n "$url_list" ]]; then
    while IFS= read -r target; do
        scan_url "$target"
    done < "$url_list"
else
    scan_url "$url"
fi
