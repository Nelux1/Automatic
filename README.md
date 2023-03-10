# Automatic.sh

For this automatic scan you need these tools:

search subdomains:
amass ( https://github.com/OWASP/Amass.git )
assetfinder ( https://github.com/tomnomnom/assetfinder.git  )
subfinder ( https://github.com/projectdiscovery/subfinder.git )

Lives subdomains:
httpx ( https://github.com/projectdiscovery/httpx.git )

Lives and screenshot:
aquatone ( https://github.com/michenriksen/aquatone.git )

Scanning CVES:
Nuclei ( https://github.com/projectdiscovery/nuclei.git ) 

Others tools:
gau ( https://github.com/lc/gau.git )
qsreplace ( https://github.com/tomnomnom/qsreplace.git )

Dictionary:
https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-110000.txt
https://github.com/projectdiscovery/nuclei-templates.git

How to install:
 Git clone https://github.com/Nelux1/Automatic
 cd Automatic
 Chmod +777 Automatic.sh
 sudo cp Automático.ah /usr/bin

How to use:
 Automático.sh example.com
