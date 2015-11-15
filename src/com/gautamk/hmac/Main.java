package com.gautamk.hmac;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {
        try {
            byte[] tests = SHA256.digest("test");
            System.out.println(tests);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
