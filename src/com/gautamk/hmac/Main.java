package com.gautamk.hmac;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
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

    public static void testSha256(boolean print) {
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
                System.out.println("Test SHA256 FAILED !!");
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

    public static void testHMAC(boolean print) {
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < 1000; i++) {
            byte[] key = new byte[secureRandom.nextInt(i + 10000)];
            byte[] message = new byte[secureRandom.nextInt(i + 10000)];

            secureRandom.nextBytes(key);
            secureRandom.nextBytes(message);
            if (print) {
                System.out.println("Testing Key");
                System.out.println(Util.bytesToHex(key));
                System.out.println("Testing Message");
                System.out.println(Util.bytesToHex(message));
            }

            try {
                byte[] stdhmac = StandardHmac.hmac(key, message);
                byte[] myhmac = HMAC.HMAC(key, message);
                if (!compare(stdhmac, myhmac)) {
                    System.out.println("Test HMAC FAILED !!");
                    return;
                }
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
                return;
            } catch (IllegalArgumentException ignored) {}
        }
        System.out.println("Test HMAC Success !!");
    }

    public static void main(String[] args) {
        String command;
        try {
            command = args[0].toLowerCase();
        } catch (ArrayIndexOutOfBoundsException e) {
            command = "hmacfile";
        }
        String keyfilename, messagefilename, outputfilename;
        switch (command) {
            case "test":
                testSha256(false);
                testHMAC(false);
                break;
            case "vtest":
                testSha256(true);
                testHMAC(true);
                break;
            case "sha256":
                break;
            case "hmac":
                byte[] hmac = HMAC.HMAC(args[1].getBytes(), args[2].getBytes());
                System.out.println(Util.bytesToHex(hmac));
                break;
            case "standardhmac":
                keyfilename = args[1];
                messagefilename = args[2];

                try {
                    byte[] key = Util.bytesFromFile(keyfilename);
                    byte[] message = Util.bytesFromFile(messagefilename);
                    byte[] s = StandardHmac.hmac(key, message);
                    System.out.println(Util.bytesToHex(s));
                } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
                    e.printStackTrace();
                }
                break;
            case "filehmac":
                keyfilename = args[1];
                messagefilename = args[2];
                outputfilename = args[3];
                try {
                    byte[] key = Util.bytesFromFile(keyfilename);
                    byte[] message = Util.bytesFromFile(messagefilename);
                    byte[] hmac1 = HMAC.HMAC(key, message);
                    String hex = Util.bytesToHex(hmac1);
                    System.out.println(hex);
                    FileOutputStream fileOutputStream = new FileOutputStream(outputfilename);
                    fileOutputStream.write(hex.getBytes());
                    fileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
        }
    }
}
