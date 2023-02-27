#!/bin/bash

url=$1

mkdir $url 
mkdir $url/recon 

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

echo -e "${GREEN}[+] Harvesting subdomains with assetfinder ++++++++++++++++++++++++++++++++${ENDCOLOR}"
assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/recon/assets.txt | wc -l
rm $url/recon/assets.txt

echo -e "${GREEN}[+] Harvesting subdomains with amass ++++++++++++++++++++++++++++${ENDCOLOR}"
amass enum -d $url >> $url/recon/s.txt
echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/recon/s.txt | wc -l
sort -u $url/recon/s.txt >> $url/recon/final.txt
rm $url/recon/s.txt

echo -e "${GREEN}[+] Lives subdomains...${ENDCOLOR}"
cat $url/recon/final.txt | httpx -silent >> $url/recon/lives.txt

#echo -e "${GREEN}[+] Lives and more subdomains...${ENDCOLOR}"
#cat $url/recon/final.txt | httpx --status-code --content-length -title -verbose  >> $url/recon/vivos.txt

echo -e "${GREEN}[+] nuclei scan...${ENDCOLOR}"
nuclei -l $url/recon/lives.txt -t cves >> $url/recon/nuclei.txt
