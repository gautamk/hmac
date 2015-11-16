package com.gautamk.hmac;

import java.nio.ByteBuffer;

/**
 * Created by gautam on 11/15/15.
 */
public class HMAC {
    private static final byte[] IPAD_BYTES = new byte[]{
            0b00110110,
            0b00110110,
            0b00110110,
            0b00110110,
            0b00110110,
            0b00110110,
            0b00110110,
            0b00110110
    };

    private static final byte[] OPAD_BYTES = new byte[]{
            0b01011100,
            0b01011100,
            0b01011100,
            0b01011100,
            0b01011100,
            0b01011100,
            0b01011100,
            0b01011100
    };
    private static final long IPAD = ByteBuffer.wrap(IPAD_BYTES).getLong();
    private static final long OPAD = ByteBuffer.wrap(OPAD_BYTES).getLong();

    private static byte[] padKey(byte[] key) {
        final int maxLength = IPAD_BYTES.length;
        byte[] paddedKey = new byte[maxLength];
        if (key.length < maxLength) {
            final int requiredZeroBytes = maxLength - key.length;
            byte[] zeroBytes = new byte[requiredZeroBytes];
            for (int i = 0; i < requiredZeroBytes; i++) {
                zeroBytes[i] = 0b00000000;
            }
            paddedKey = Util.concat(zeroBytes, key);
        } else {
            System.arraycopy(key, 0, paddedKey, 0, maxLength);
        }
        return paddedKey;
    }

    public static byte[] HMAC(byte[] key, byte[] message) {
        long paddedKey = ByteBuffer.wrap(padKey(key)).getLong();

        long ipadXorKey = IPAD ^ paddedKey;
        long opadXorKey = OPAD ^ paddedKey;

        byte[] ipadXorKeyBytes = ByteBuffer.allocate(8).putLong(ipadXorKey).array();
        byte[] opadXorKeyBytes = ByteBuffer.allocate(8).putLong(opadXorKey).array();

        byte[] iPadDigest = SHA256.digest(Util.concat(ipadXorKeyBytes, message));
        byte[] hmac = SHA256.digest(Util.concat(opadXorKeyBytes, iPadDigest));

        return hmac;
    }
}
