package com.gautamk.hmac;

/**
 * Created by gautam on 11/15/15.
 */
public class HMAC {
    private static int BLOCK_SIZE = 64;
    private static final byte[] IPAD = new byte[BLOCK_SIZE];
    private static final byte[] OPAD = new byte[BLOCK_SIZE];

    static {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            IPAD[i] = 0b00110110;
            OPAD[i] = 0b01011100;
        }
    }

    private static byte[] padKey(byte[] key) {

        byte[] paddedKey = new byte[BLOCK_SIZE];
        if (key.length > BLOCK_SIZE) {
            key = SHA256.digest(key);
        }
        if (key.length < BLOCK_SIZE) {
            final int requiredZeroBytes = BLOCK_SIZE - key.length;
            byte[] zeroBytes = new byte[requiredZeroBytes];
            for (int i = 0; i < requiredZeroBytes; i++) {
                zeroBytes[i] = 0b00000000;
            }
            paddedKey = Util.concat(key, zeroBytes);
        }

        if (key.length == BLOCK_SIZE) {
            paddedKey = key;
        }
        return paddedKey;
    }

    public static byte[] HMAC(byte[] key, byte[] message) {
        byte[] paddedKey = padKey(key);

        byte[] ipadXorKey = Util.xor(IPAD, paddedKey);
        byte[] opadXorKey = Util.xor(OPAD, paddedKey);

        byte[] iPadDigest = SHA256.digest(Util.concat(ipadXorKey, message));
        byte[] hmac = SHA256.digest(Util.concat(opadXorKey, iPadDigest));

        return hmac;
    }
}
