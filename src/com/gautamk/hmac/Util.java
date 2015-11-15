package com.gautamk.hmac;

/**
 * Created by gautam on 11/15/15.
 */
public class Util {

    public static String toBinaryString(long[] longs) {
        StringBuilder stringBuilder = new StringBuilder();
        for (long aLong : longs) {
            String s = Long.toBinaryString(aLong);
            stringBuilder.append(s);
        }
        return stringBuilder.toString();
    }

    private static long[] concat(long[] a, long[] b) {
        int aLen = a.length;
        int bLen = b.length;
        long[] c = new long[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    static long[] concat(long[] a, long b) {
        long[] one = new long[1];
        one[0] = b;
        return concat(a, one);
    }



}
