package com.gautamk.hmac;

import java.nio.ByteBuffer;

/**
 * Created by gautam on 11/15/15.
 */
public class Util {

    protected final static char[] hexArray = "0123456789ABCDEF".toCharArray();

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

    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    public static int fromByteArray(byte[] bytes) {
        return ByteBuffer.wrap(bytes).getInt();
    }

    public static byte[] toByteArray(int theInt) {
        return ByteBuffer.allocate(4).putInt(theInt).array();
    }

    /**
     * Sourced from http://stackoverflow.com/a/9855338/492561
     *
     * @param bytes
     * @return
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


}
