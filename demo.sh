#!/bin/bash
echo "HMAC - SHA256 Implementation in java by Gautam Kumar"
echo "Usage:"
echo "java -cp JHmac.jar com.gautamk.hmac.Main filehmac <keyfile> <messagefile> <outputfile>"
echo "java -cp JHmac.jar com.gautamk.hmac.Main test # This tests my SHA256 and the HMAC implementations with inbuilt implementations"
javac src/com/gautamk/hmac/*.java -d .
jar cvf JHmac.jar com
echo "ThisIsASecretKey" > keyfile
echo "ThisIsASecretMessage" > messagefile
java -cp JHmac.jar com.gautamk.hmac.Main filehmac keyfile messagefile outputfile