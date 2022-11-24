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

## Tools 

### Must have tools

This are a pack of tools I always use. Here are the basic utilities:
```console
zero@pio$ sudo apt install curl nmap neovim git sqsh pip python3-pip samba-client python3-ldap3 python3-yaml python3-impacket python3-venv freerdp2-x11 build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm sqlitebrowser mariadb-client-core-10.6 python2-minimal
```

Here the tools:
```console
zero@pio$ sudo apt install nmap hashcat ffuf hydra zaproxy maltego seclists enum4linux smbclient eyewitness john crackmapexec evil-winrm sqlmap burpsuite chisel responder hydra wpscan exploitdb bloodhound neo4j wordlists windows-binaries mimikatz hash-identifier whatweb libimage-exiftool-perl foremost netdiscover
```

Python tools:
```console
zero@pio$ pip install pypykatz pycrypto
```

### Docker Tools

First install Docker:
```console
zero@pio$ sudo apt install -y docker.io
zero@pio$ sudo systemctl enable docker --now
zero@pio$ sudo usermod -aG docker $USER
```

Then we install rustscan:
```console
zero@pio$ rustscan/rustscan:latest
```

To use it add the alias:
```
alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:alpine'
```

### Made tools

Use impacket tools from any path:
```console
zero@pio$ git clone https://github.com/SecureAuthCorp/impacket
zero@pio$ cd impacket; sudo python3 -m pip install .
```

> Maybe you need to install crackmapexec after Impacket.
{: .prompt-tip}

Use kerbrute from any path:
```console
zero@pio$ wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
zero@pio$ chmod +x ./kerbrute_linux_amd64; sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

### AD Utility

Download the scripts:
```console
zero@pio$ wget https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1
zero@pio$ wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
zero@pio$ wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.54/Snaffler.exe
```

## Firefox

Add the **Wappalyzer**, **FoxyProxy** and **Cookie Editor** to Firefox. Remove the `Ask to save login passwords...` and change the browser by DuckDuckGo.

Remember to download Burp (visiting `http://burp` with the proxy set) and ZAP (inside Settings) certs for the browser and install them.

## Rockyou 

Unzip rockyou (`sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`)

## CPU

For CPU usage in the machine (for hashcat) we need to install:
```
zero@pio$ sudo apt install libhwloc-dev ocl-icd-dev ocl-icd-opencl-dev pocl-opencl-icd
```

## Update the system

```console
zero@pio$ sudo apt update --fix-missing; sudo apt upgrade -y; sudo apt autoremove -y; sudo apt autoclean -y
```

## C2

### Covenant

In another machine we will build a Debian Server. Now we will follow the [Covenant installation](https://github.com/cobbr/Covenant/wiki/Installation-And-Startup) with Docker. To launch it:
```console
zeroc2@c2server$ docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /home/zeroc2/Covenant/Covenant/Data:/app/Data covenant
```

### Havoc

Follow the installation in the server for the **TeamServer** and the same for the **Client** in the Kali for [Havoc](https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD#install).

Once installed, modify the `profiles/havoc.yaotl`{: .filepath} to create or own users. To launch the C2, inside `Havoc/TeamServer`{: .filepath}:
```console
zeroc2@c2server$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

---

# For Malware 

Always keep these machines in a VM, for a safe controlled enviroment. Also keeps them host-only in a isolated network, recommendable to be a different IP range from the home network (for example **10.0.0....**). You may need to add the following lines to a created file `/etc/vbox/networks.conf`{: .filepath} to could be able to create the network:
```
* 10.0.0.0/8 192.168.0.0/16
* 2001::/64
```

The Linux host (REMnux) will be a Internet simulator, to make the malware thinks that he has Internet connection.

## Windows

With a Windows 10 VM we will install:
```
x32dbg
x64dbg
dnSpy
Sysinternals
cutter
PE-bear
Resource Hacker
IDA Freeware
Process Hacker 2
Visual Studio (C++)
Notepadd++
Cmder
```

Also disable the Windows Updates, Cortana and Defender.

## For Linux 

In this page, we can get the [REMnux](https://remnux.org/#distro) distro, for Malware Analysis. For simulate the network we will use `inetsim`. Go to the config file `/etc/inetsim/inetsim.conf`{: .filepath}. Uncomment the line:
```bash
start_service dns
```

In the **service_bind_address** uncomment the last line and change the IP to:
```bash
service_bind_address    0.0.0.0
```

In the **dns_default_ip** uncomment the last line and change the IP to the REMnux IP:
```bash
dns_default_ip          10.0.0.3
```

Now run the service:
```console
remnux@remnux:~$ inetsim
```

Then we can also download the **Mobile Security Framework - MobSF** from [Docker](https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf) as:
```console
remnux@remnux:~$ docker pull opensecurity/mobile-security-framework-mobsf
remnux@remnux:~$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

If we go to Internet in the Windows VM and navigate to the Linux IP with http, https... we would see some default pages, meaning the service is working. If we search anything in the http and add **/<something>.exe** it will download an inetsim binary, to simulate for the malware a file downloading. Now change the default DNS for the Windows Host to be the REMnux, so if we type any domain it will redirect us to the inetsim default page.

---

Feel free to copy it and install.

> It will be increasing since I'm progressing.
{: .prompt-info }
