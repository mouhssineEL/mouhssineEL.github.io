---
title: Notes | Tools
author: Zeropio
date: 2022-07-14
categories: [Notes, Tools]
tags: []
permalink: /notes/tools
---

This are my personal selection of **must have** tools for pentesting, bug bounty, CTFs or machines:

# For Linux

This is the path I choose while setting a Kali:

## Must have tools

```
netcat
curl
nmap
hashcat
ffuf
hydra
zaproxy
maltego
seclists
nvim
smtp-user-enum 
eyewitness
crackmapexec
```

## Made tools

Use impacket tools from any path:
```console
zero@pio$ git clone https://github.com/SecureAuthCorp/impacket
zero@pio$ sudo python3 -m pip install .
```

Use kerbrute from any path:
```console
zero@pio$ wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
zero@pio$ chmod + x ./kerbrute_linux_amd64; sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

## Certs 

Remember to download Burp (visiting `http://burp` with the proxy set) and ZAP (inside Settings) certs for the browser and install them.

## Rockyou 

Unzip rockyou (`sudo gzip -d /usr/share/wordlist/rockyou.txt.gz`)

## Update the system

```console
zero@pio$ sudo apt update --fix-missing; sudo apt upgrade -y; sudo apt autoremove -y; sudo apt autoclean -y
```

---

# For Windows

```
python
vscode
git
wsl2
openssh
openvpn
x32dbg
x64dbg
dnSpy
ysoserial.net
```

## Chocolatey

Install from [here](https://chocolatey.org/). In an administrator PowerShell:
```console
PS C:\> Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

## Install 

Now for install with Chocolatey:
```console
PS C:\> choco install python
PS C:\> choco install vscodium
PS C:\> choco install git
PS C:\> choco install wsl2
PS C:\> choco install openssh
PS C:\> choco install openvpn
PS C:\> choco install brave
```

Download the lastest version of [x64dbg](https://github.com/x64dbg/x64dbg/releases/tag/snapshot), [dnSpy](https://github.com/dnSpy/dnSpy/releases/tag/v6.1.8) and [ysoserial.net](https://github.com/frohoff/ysoserial/releases).

---

# For Malware Analysis 

## Windows

Use a Windows 10 VM (not main OS) and using the [Flare VM](https://github.com/mandiant/flare-vm) github we will use this [PowerShell Script](https://raw.githubusercontent.com/mandiant/flare-vm/master/install.ps1) to make a full installation.

## For Linux 

In this page, we can get the [REMnux](https://remnux.org/#distro) distro, for Malware Analysis.

---

Feel free to copy it and install.

> It will be increasing since I'm progressing.
{: .prompt-info }
