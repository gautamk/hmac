package com.gautamk.hmac;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {
    private static boolean compare(byte[] a, byte[] b) {

        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    public static void test(boolean print) {
        SecureRandom secureRandom = new SecureRandom();
        MessageDigest instance = null;
        try {
            instance = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        long l = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            byte[] d = new byte[secureRandom.nextInt(i + 10000)];
            secureRandom.nextBytes(d);
            if (print) {
                System.out.println("Testing ");
                System.out.println(Util.bytesToHex(d));
            }

            byte[] myDigest = SHA256.digest(d);
            byte[] inbuiltDigest = instance.digest(d);

            if (print) {
                System.out.print("My Digest ");
                System.out.println(Util.bytesToHex(myDigest));
                System.out.print("Inbuilt Digest ");
                System.out.println(Util.bytesToHex(inbuiltDigest));
            }
            if (!compare(myDigest, inbuiltDigest)) {
                System.out.println("Test FAILED !!");
                if (!print) {
                    System.out.println("Testing ");
                    System.out.println(Util.bytesToHex(d));
                    System.out.print("My Digest ");
                    System.out.println(Util.bytesToHex(myDigest));
                    System.out.print("Inbuilt Digest ");
                    System.out.println(Util.bytesToHex(inbuiltDigest));
                }
                return;
            }
        }
        System.out.println("Testing SHA256 Successful in " + (System.currentTimeMillis() - l) + "ms");
    }

    public static void main(String[] args) {
        switch (args[0].toLowerCase()) {
            case "test":
                test(false);
                break;
            case "vtest":
                test(true);
                break;
            case "sha256":
                break;
            case "hmac":
                byte[] hmac = HMAC.HMAC(args[1].getBytes(), args[2].getBytes());
                System.out.println(Util.bytesToHex(hmac));

        }
    }
}
