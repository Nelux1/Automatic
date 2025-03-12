#!/bin/bash

banner="

     e                 d8                                      d8   ,e,
    d8b     888  888 _d88__  e88~-_  888-~88e-~88e   /~~~8e  _d88__      e88~~\

   /Y88b    888  888  888   d888   i 888  888  888       88b  888   888 d888
  /  Y88b   888  888  888   8888   | 888  888  888  e88~-888  888   888 8888
 /____Y88b  888  888  888   Y888   | 888  888  888 C888  888  888   888 Y888
/      Y88b  88_-888   88_/   88_-~  888  888  888   88_-888   88_/ 888   88__/

"

echo -e "$banner"

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

echo -e "${GREEN} Harvesting subdomains with rapidns +++++++++++++++++++++++++++${ENDCOLOR}"
rapiddns(){
    curl -s "https://rapiddns.io/subdomain/$1?full=1" | \
    sed -e 's/<[^>]*>//g' | \
    grep -oP '([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+' | \
    sort -u
}
rapiddns $url | tee -a $url/rapid.txt
cat $url/rapid.txt | grep $1 | tee -a $url/final.txt
echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/rapid.txt | wc -l
rm $url/rapid.txt

echo -e "${GREEN} Harvesting subdomains with crt +++++++++++++++++++++++++++${ENDCOLOR}"
crt(){
 curl -s "https://crt.sh/?q=%25.$1" | \
    sed -e 's/<[^>]*>//g' | \
    grep -oP '([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+' | \
    sort -u
}
crt $url | tee -a $url/crt.txt
cat $url/crt.txt | grep $1 | tee -a $url/final.txt
echo -e "${RED}subdomains found:${ENDCOLOR}"
cat $url/crt.txt | wc -l
rm $url/crt.txt

echo -e "${GREEN}[+] Lives subdomains and more...${ENDCOLOR}"
cat $url/final.txt | httpx -silent >> $url/lives.txt
cat $url/lives.txt | httpx -silent -p  80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 >> $url/ports.txt
cat $url/final.txt | httpx --status-code --content-length -title -fr -verbose  >> $url/vivos.txt
cat $url/ports.txt | httpx -ss -t 20 -system-chrome 

echo -e "${GREEN}[+] All urls lives...${ENDCOLOR}"
cat $url/lives.txt | gau --subs | egrep -iv ".(jpg|peg|gif|tif|tiff|png|woff|woff2|ico|svg)" | httpx -silent | tee -a $url/allurls.txt

echo -e "${GREEN}[+] nuclei scan all outputs...${ENDCOLOR}"
nuclei -l $url/lives.txt -t ~/nuclei-templates -es info | tee -a $url/nuclei.txt
nuclei -l $url/allurls.txt -t ~/nuclei-templates -es info | tee -a $url/allurls_nuclei.txt


echo -e "${GREEN}[+] Scan xss...${ENDCOLOR}"
cat $url/allurls.txt | tee -a $url/archivo.txt | grep "=" | egrep -iv ".(jpg|peg|gif|css|tif|tiff|png|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace '"><script>confirm(1)</script>'| tee -a $url/arch.json && cat $url/arch.json | while read host do; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;031mVulnerable\n" | tee -a $url/xss_vulnerables.txt;done
rm $url/archivo.txt
rm $url/arch.json

cat $url/allurls.txt | grep "="| uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | tee -a $url/xss_vulnerables.txt


cat $url/lives.txt | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H "Origin:evil.com" {} | [[ $(grep -c "evil.com") -gt 0 ]] && printf "\n\033[0;32m[VUL TO CORS] - {}\e[m"' 2>/dev/null | tee -a $url/cors.txt

# Si el archivo está vacío, lo borra
[[ ! -s $url/cors.txt ]] && rm $url/cors.txt
