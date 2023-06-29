<a href='https://cafecito.app/nelux' rel='noopener' target='_blank'><img srcset='https://cdn.cafecito.app/imgs/buttons/button_6.png 1x, https://cdn.cafecito.app/imgs/buttons/button_6_2x.png 2x, https://cdn.cafecito.app/imgs/buttons/button_6_3.75x.png 3.75x' src='https://cdn.cafecito.app/imgs/buttons/button_6.png' alt='Invitame un café en cafecito.app' /></a>

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

For cors install:
rush

How to install:
 Git clone https://github.com/Nelux1/Automatic
 cd Automatic
 Chmod +777 Automatic.sh
 sudo cp Automatic.sh /usr/bin

How to use:
 Automatic.sh example.com

you can disable the commands you want by adding "#" before starting the line.
