package com.gautamk.hmac;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) {
        try {
            String test = "TestString";
            byte[] digest = SHA256.digest(test);
            String myResult = Util.bytesToHex(digest);
            System.out.println("MyResult: " + myResult);

            MessageDigest inbuiltSha256 = MessageDigest.getInstance("SHA-256");
            String inbuiltResult = Util.bytesToHex(inbuiltSha256.digest(test.getBytes()));
            System.out.println("InbuiltResult: " + inbuiltResult);

            System.out.println("MyResult == InbuiltResult: " + myResult.equals(inbuiltResult));
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
