#!/bin/bash

url=$1

mkdir $url

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

echo -e "${GREEN}[+] Harvesting subdomains with assetfinder ++++++++++++++++++++++++++++++++${ENDCOLOR}"
assetfinder $url >> $url/assets.txt
cat $url/assets.txt | grep $1 >> $url/final.txt
echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/assets.txt | wc -l
rm $url/assets.txt

echo -e "${GREEN} Harvesting subdomains with subfinder +++++++++++++++++++++++++++${ENDCOLOR}"
subfinder -d $url -silent >> $url/sub.txt
cat $url/sub.txt | grep $1 | tee -a $url/final.txt
echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/sub.txt | wc -l
rm $url/sub.txt

echo -e "${GREEN}[+] Harvesting subdomains with amass ++++++++++++++++++++++++++++${ENDCOLOR}"
amass enum -d $url >> $url/amass.txt
amass enum -active -d $url -brute -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt | tee -a $url/amass.txt
cat $url/amass.txt | aquatone -ports xlarge -out $url/aqua_$url

echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/amass.txt | wc -l
sort -u $url/amass.txt >> $url/final.txt
rm $url/amass.txt

echo -e "${GREEN}[+] Lives subdomains...${ENDCOLOR}"
cat $url/final.txt | httpx -silent >> $url/lives.txt

echo -e "${GREEN}[+] Lives and more subdomains...${ENDCOLOR}"
cat $url/final.txt | httpx --status-code --content-length -title -verbose  >> $url/vivos.txt

echo -e "${GREEN}[+] nuclei scan...${ENDCOLOR}"
nuclei -l $url/lives.txt -t cves >> $url/nuclei.txt
nuclei -l $url/lives.txt -t ~/nuclei-templates -es info | tee -a $url/nuclei.txt  
nuclei -l $url/aqua_$url/aquatone_urls.txt -t ~/nuclei-templates -es info | tee -a $url/nuclei.txt 
nuclei -l $url/aqua_$url -t cves | tee -a $url/nuclei.txt

echo -e "${GREEN}[+] Scan xss...${ENDCOLOR}"
cat $url/lives.txt | gau --subs | tee -a $url/archivo.txt | grep "=" | egrep -iv ".(jpg|peg|gif|css|tif|tiff|png|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace '"><script>confirm(1)</script>'| tee -a $url/arch.json && cat $url/arch.json | while read host do; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;031mVulnerable\n" | tee -a $url/xss_vulnerables.txt;done
rm $url/archivo.txt
rm $url/arch.json
