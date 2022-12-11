---
title: Notes | AD Resources
author: Zeropio
date: 2022-08-15
categories: [Notes, System]
tags: [windows, ad]
permalink: /notes/system/ad-resources
---

# Resources

| **Link**   | **Description**    |
|--------------- | --------------- |
| **General** |
| [PowerView](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView) | these tools can be used as replacements for various Windows `net*` commands and more |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Impacket is a collection of Python classes for working with network protocols |
| [Responder](https://github.com/lgandx/Responder) | LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication |
| [Inveigh.ps1](https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1) | Similar to Responder |
| [C# Inveigh](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh) | C# version of Inveigh |
| [Hashcat](https://hashcat.net/hashcat/) | hash cracking and password recovery tool |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service |
| [ldapsearch](https://linux.die.net/man/1/ldapsearch) | built-in interface for interacting with the LDAP protocol |
| [smbserver.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py) | Simple SMB server execution for interaction with Windows hosts |
| [mssqlclient.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/mssqlclient.py) | provides the ability to interact with MSSQL databases |
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) | parse the Group Policy Preferences XML file which extracts the username and decrypts the cpassword attribute |
| [PingCastle](https://www.pingcastle.com/documentation/) | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework |
| **Enumeration** |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Six Degrees of Domain Admin |
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) | data collector to gather information from AD |
| [BloodHound.py](https://github.com/fox-it/BloodHound.py) | A Python based ingestor for BloodHound |
| [Kerbrute](https://github.com/ropnop/kerbrute) | A tool to perform Kerberos pre-auth bruteforcing |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) (CME) | A swiss army knife for pentesting networks |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) | a Linux alternative to enum.exe for enumerating data from Windows and Samba hosts |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | A next generation version of enum4linux |
| [windapsearch](https://github.com/ropnop/windapsearch) | Python script to enumerate users, groups and computers from a Windows domain through LDAP queries |
| [SMBMap](https://github.com/ShawnDEvans/smbmap) | SMBMap is a handy SMB enumeration tool |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Useful for finding information in Active Directory on computers with accessible file shares |
| [rpcdump.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py) |  RPC endpoint mapper |
| [ADIDNSdump](https://github.com/dirkjanm/adidnsdump) | Active Directory Integrated DNS dumping by any authenticated user |
| [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | is an AD viewer and editor |
| [ADRecon](https://github.com/adrecon/ADRecon) | tool which gathers information about the Active Directory and generates a report  |
| **Attack** |
| [Rubeus](https://github.com/GhostPack/Rubeus) | tool built for Kerberos Abuse |
| [GetUserSPNs.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py) | finding Service Principal names tied to normal users | 
| [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) | perform a password spray attack against users of a domain |
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) | Tool to audit and attack LAPS environments |
| [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py) | provides us with Psexec-like functionality in the form of a semi-interactive shell |
| [wmiexc.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/wmiexec.py) | provides the capability of command execution over WMI |
| [secretsdump.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/secretsdump.py) | Remotely dump SAM and LSA secrets from a host |
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) | Adds, reads, modifies and deletes the Service Principal Names directory property for an Active Directory service account |
| [mimikatz](https://github.com/ParrotSec/mimikatz) | Performs many functions |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | The ultimate WinRM shell for hacking/pentesting |
| [noPac](https://github.com/Ridter/noPac) | Exploiting CVE-2021-42278 and CVE-2021-42287 |
| [CVE-2021-1675.py](https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py) | Printnightmare PoC |
| [ntlmrelayx.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ntlmrelayx.py) | performs SMB relay attacks |
| [PetitPotam](https://github.com/topotam/PetitPotam) | PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions |
| [gettgtgpkinit.py](https://raw.githubusercontent.com/dirkjanm/PKINITtools/master/gettgtpkinit.py) | manipulating certificates and TGTs |
| [getnthash.py](https://raw.githubusercontent.com/dirkjanm/PKINITtools/master/getnthash.py) | use an existing TGT to request a PAC for the current user using U2U |
| [GetNPUsers.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py) | perform the ASREPRoasting attack to list and obtain AS-REP hashes for users |
| [lookupsid.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/lookupsid.py) | SID bruteforcing tool 1
| [ticketer.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ticketer.py) | creation and customization of TGT/TGS tickets |
| [raiseChild.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/raiseChild.py) | automated child to parent domain privilege escalation | 
| [Group3r](https://github.com/Group3r/Group3r) | Find vulnerabilities in AD Group Policy 

