#!/bin/bash
# Part two of a bash script to install the packages recommended by Peter Kim in The Hacker Playbook 2
# http://www.amazon.com/dp/1512214566/

# Since Peter's book is based off of the Kali Linux platform, you can download the Kali Linux distro from: http://www.kali.org/downloads/. I highly recommend you download the VMware image (https://www.offensive-security.com/kali-linux-vmware-arm-image-download/) and download Virtual Player/VirtualBox. Remember that it will be a gz-compressed and tar archived file, so make sure to extract them first and load the vmx file.

#FIXES ERROR IN SMBEXEC SCRIPT (DEAD LINK)
cd /opt && git clone https://github.com/csababarta/ntdsxtract /opt/NTDSXtract
cd /opt/NTDSXtract && /usr/bin/python ./setup.py build install
cd /opt && git clone  https://github.com/infoassure/dumpntds /opt/dumpntds
cd /opt/dumpntds && ln -s dshashes.py /opt/NTDSXtract/


#Tool Installation
#The Backdoor Factory:
#	Patch PE, ELF, Mach-O binaries with shellcode.
cd /opt && git clone https://github.com/secretsquirrel/the-backdoor-factory /opt/the-backdoor-factory
cd /opt/the-backdoor-factory
./install.sh

#HTTPScreenShot
#	HTTPScreenshot is a tool for grabbing screenshots and HTML of large numbers of websites.
pip install selenium
cd /opt && git clone https://github.com/breenmachine/httpscreenshot.git /opt/httpscreenshot
cd /opt/httpscreenshot
chmod +x install-dependencies.sh && ./install-dependencies.sh
#	HTTPScreenShot only works if you are running on a 64-bit Kali by default. If you are running 32-bit PAE, install i686 phatomjs as follows:
#wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.8-linux-i686.tar.bz2
#bzip2 -d phantomjs-1.9.8-linux-i686.tar.bz2
#tar xvf phantomjs-1.9.8-linux-i686.tar
#cp phantomjs-1.9.8-linux-i686/bin/phantomjs /usr/bin/

#SMBExec
#	A rapid psexec style attack with samba tools.
cd /opt && git clone https://github.com/pentestgeek/smbexec.git /opt/smbexec
cd /opt/smbexec && ./install.sh
#	Select 1 - Debian/Ubuntu and derivatives
#	Select all defaults
./install.sh
#	Select 4 to compile smbexec binaries
#	After compilation, select 5 to exit
#Masscan
#	This is the fastest Internet port scanner. It can scan the entire Internet in under six minutes.
apt-get install git gcc make libpcap-dev
cd /opt && git clone https://github.com/robertdavidgraham/masscan.git /opt/masscan
cd /opt/masscan
make
make install

#Gitrob
#	Reconnaissance tool for GitHub organizations
cd /opt && git clone https://github.com/michenriksen/gitrob.git /opt/gitrob
gem install bundler
#service postgresql start
#su postgres
#createuser -s gitrob --pwprompt
#createdb -O gitrob gitrob
#exit
cd /opt/gitrob/bin
gem install gitrob

#CMSmap
#	CMSmap is a python open source CMS (Content Management System) scanner that automates the process of detecting security flaws
#	cd /opt && git clone https://github.com/Dionach/CMSmap /opt/CMSmap

#WPScan
#	WordPress vulnerability scanner and brute-force tool
cd /opt && git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
cd /opt/wpscan && ./wpscan.rb --update

#Eyewitness
#	EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
cd /opt && git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness

#Printer Exploits
#	Contains a number of commonly found printer exploits
cd /opt && git clone https://github.com/MooseDojo/praedasploit /opt/praedasploit

#SQLMap
#	SQL Injection tool
cd /opt && git clone https://github.com/sqlmapproject/sqlmap /opt/sqlmap

Recon-ng
#	A full-featured web reconnaissance framework written in Python
cd /opt && git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git /opt/recon-ng

#Discover Scripts
#	Custom bash scripts used to automate various pentesting tasks.
#	cd /opt && git clone https://github.com/leebaird/discover.git /opt/discover
cd /opt/discover && ./update.sh

#BeEF Exploitation Framework
#	A cross-site scripting attack framework
cd /opt/ && mkdir beef && cd beef/ && wget https://raw.github.com/beefproject/beef/a6a7536e/install-beef
chmod +x install-beef
./install-beef

#Responder
#	A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. Responder will be used to gain NTLM challenge/response hashes
cd /opt && git clone https://github.com/SpiderLabs/Responder.git /opt/Responder

#The Hacker Playbook 2 - Custom Scripts
#	A number of custom scripts written by myself for The Hacker Playbook 2.
cd /opt && git clone https://github.com/cheetz/Easy-P.git /opt/Easy-P
cd /opt && git clone https://github.com/cheetz/Password_Plus_One /opt/Password_Plus_One
cd /opt && git clone https://github.com/cheetz/PowerShell_Popup /opt/PowerShell_Popup
cd /opt && git clone https://github.com/cheetz/icmpshock /opt/icmpshock
cd /opt && git clone https://github.com/cheetz/brutescrape /opt/brutescrape
cd /opt && git clone https://www.github.com/cheetz/reddit_xss /opt/reddit_xss

#The Hacker Playbook 2 - Forked Versions
#	Forked versions of PowerSploit and Powertools used in the book. Make sure you clone your own repositories from the original sources.
cd /opt && git clone https://github.com/cheetz/PowerSploit /opt/HP_PowerSploit
cd /opt && git clone https://github.com/cheetz/PowerTools /opt/HP_PowerTools
cd /opt && git clone https://githubmkdir dshashes && cd dshashes && wget -q https://raw.githubusercontent.com/lanmaster53/ptscripts/master/dshashes.py

#SPARTA:
#	A python GUI application which simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phase.
cd /opt && git clone https://github.com/secforce/sparta.git /opt/sparta
apt-get install python-elixir
apt-get install ldap-utils rwho rsh-client x11-apps finger

#NoSQLMap
#	A automated pentesting toolset for MongoDB database servers and web applications.
cd /opt && git clone https://github.com/tcstool/NoSQLMap.git /opt/NoSQLMap

#Spiderfoot
#	Open Source Footprinting Tool
mkdir /opt/spiderfoot/ && cd /opt/spiderfoot
wget http://sourceforge.net/projects/spiderfoot/files/spiderfoot-2.3.0-src.tar.gz/download
tar xzvf download
pip install lxml
pip install netaddr
pip install M2Crypto
pip install cherrypy
pip install mako


# WCE
#	Windows Credential Editor (WCE) is used to pull passwords from memory
#	Download from: http://www.ampliasecurity.com/research/windows-credentials-editor/ and save to /opt/. For example:
wget www.ampliasecurity.com/research/wce_v1_4beta_universal.zip
mkdir /opt/wce && unzip wce_v1* -d /opt/wce && rm wce_v1*.zip

#Mimikatz
#	Used for pulling cleartext passwords from memory, Golden Ticket, skeleton key and more
#	Grab the newest release from https://github.com/gentilkiwi/mimikatz/releases/latest
cd /opt/ && wget http://blog.gentilkiwi.com/downloads/mimikatz_trunk.zip
unzip -d ./mimikatz mimikatz_trunk.zip

#SET
#	Social Engineering Toolkit (SET) will be used for the social engineering campaigns
cd /opt && git clone https://github.com/trustedsec/social-engineer-toolkit/ /opt/set/
cd /opt/set && ./setup.py install

# PowerSploit (PowerShell)
#	PowerShell scripts for post exploitation
cd /opt && git clone https://github.com/mattifestation/PowerSploit.git /opt/PowerSploit
cd /opt/PowerSploit && wget https://raw.githubusercontent.com/obscuresec/random/master/StartListener.py && wget https://raw.githubusercontent.com/darkoperator/powershell_scripts/master/ps_encoder.py

#Nishang (PowerShell)
#	Collection of PowerShell scripts for exploitation and post exploitation
cd /opt && git clone https://github.com/samratashok/nishang /opt/nishang

#Veil-Framework
#	A red team toolkit focused on evading detection. It currently contains Veil-Evasion for generating AV-evading payloads, Veil-Catapult for delivering them to targets, and Veil-PowerView for gaining situational awareness on Windows domains. Veil will be used to create a python based Meterpreter executable.
cd /opt && git clone https://github.com/Veil-Framework/Veil /opt/Veil
cd /opt/Veil/ && ./Install.sh -c

#Burp Suite Pro
#	Web Penetration Testing Tool
#	Download: http://portswigger.net/burp/proxy.html. I would highly recommend that you buy the professional version. It is well worth the $299 price tag.

#ZAP Proxy Pro
#	OWASP ZAP: An easy-to-use integrated penetration testing tool for discovering vulnerabilities in web applications.
#	Download from: https://code.google.com/p/zaproxy/wiki/Downloads?tm=2
#	*Included by default in Kali Linux (owasp-zap)

#Fuzzing Lists (SecLists)
#	These are scripts to use with Burp to fuzz parameters
cd /opt && git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

#Password Lists
#	For the different password lists, see the section: Special Teams - Cracking, Exploits, and Tricks

#Net-Creds Network Parsing 
#	Parse PCAP files for username/passwords
cd /opt && git clone https://github.com/DanMcInerney/net-creds.git /opt/net-creds

#Installing Firefox Add-ons
#	Web Developer Add-on: https://addons.mozilla.org/en-US/firefox/addon/web-developer/
#	Tamper Data: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
#	Foxy Proxy: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
#	User Agent Switcher: https://addons.mozilla.org/en-US/firefox/addon/user-agent-switcher/

#Wifite
#	Attacks against WiFi networks
cd /opt && git clone https://github.com/derv82/wifite /opt/wifite

#WIFIPhisher
#	Automated phishing attacks against WiFi networks
cd /opt && git clone https://github.com/sophron/wifiphisher.git /opt/wifiphisher

#Phishing (Optional):
#	Phishing-Frenzy
cd /opt && git clone https://github.com/pentestgeek/phishing-frenzy.git /var/www/phishing-frenzy
#	Custom List of Extras
git clone https://github.com/macubergeek/gitlist.git /opt/gitlist

#*Remember to check http://thehackerplaybook.com/updates/ for any updates.
wget https://raw.githubusercontent.com/brad-anton/freeradius-wpe/master/freeradius-wpe.patch


