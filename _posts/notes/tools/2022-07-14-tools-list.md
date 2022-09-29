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

---

# For Malware Analysis 

Always keep these machines in a VM, for a safe controlled enviroment. Also keeps them host-only in a isolated network, recommendable to be a different IP range from the home network (for example **10.0.0....**). You may need to add the following lines to a created file `/etc/vbox/networks.conf`{: .filepath} to could be able to create the network:
```
* 10.0.0.0/8 192.168.0.0/16
* 2001::/64
```

The Linux host (REMnux) will be a Internet simulator, to make the malware thinks that he has Internet connection.

## Windows

Use a Windows 10 VM (not main OS) and using the [Flare VM](https://github.com/mandiant/flare-vm) github we will use this [PowerShell Script](https://raw.githubusercontent.com/mandiant/flare-vm/master/install.ps1) to make a full installation. Install then [pestudio](https://www.winitor.com/download2). 

For my own choose, I add in the taskbar some programs like the file system, cutter, cmder, x34dbg, x64dbg, dnSpy... (customize then to make the letter bigger).

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
