#!/bin/bash

javac src/com/gautamk/hmac/*.java -d .
jar cvf JHMac.jar com
echo "ThisIsASecretKey" > keyfile
echo "ThisIsASecretMessage" > messagefile
java -cp JHMac.jar com.gautamk.hmac.Main filehmac keyfile messagefile outputfile