package com.gautamk.hmac;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.BitSet;

/**
 * Created by gautam on 11/14/15.
 */
public class Sha256 {
    public static int[] H = {
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19
    };

    /**
     * Suppose that the length of the message, M, is L bits. Append the bit “1” to the end of the
     * message, followed by k zero bits, where k is the smallest, non-negative solution to the equation
     * L + 1 + k ≡ 448mod512 . Then append the 64-bit block that is equal to the number L expressed
     * using a binary representation. For example, the (8-bit ASCII) message “abc” has length
     * 8× 3 = 24 , so the message is padded with a one bit, then 448 − (24 +1) = 423 zero bits, and then
     * the message length, to become the 512-bit padded message
     *
     * @param message
     * @return
     */
    public static byte[] applyPadding(byte[] message) {
        long messageByteLength = message.length;
        long messageBitLength = messageByteLength * 8;

        // L + 1 + k ≡ 448mod512
        // K ≡ 448 mod 512 - L - 1
        long K = (448 % 512) - messageBitLength - 1;
        long sizeOfMessageLength = 64; // i.e sizeOf messageBitLength
        long paddedBitLength = messageBitLength + 1 + K + sizeOfMessageLength;
        long paddedByteLength = paddedBitLength / 8;
        BitSet messageBitSet = BitSet.valueOf(message);

        // Append 1
        messageBitSet.set((int) messageBitLength, true);

        int start = (int) (messageBitLength + 1);
        int end = (int) (messageBitLength + 1 + K);
        // Set append K 0 bits
        
//        messageBitSet.set(start, end, false);

        long[] concat = Util.concat(messageBitSet.toLongArray(), messageBitLength);
        BitSet paddedBitSet = BitSet.valueOf(concat);

        return paddedBitSet.toByteArray();
    }

    public static byte[] digest(byte[] message) {
        return applyPadding(message);
    }


    public static byte[] digest(File file) throws IOException {
        FileInputStream stream = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        return digest(data);
    }

    public static byte[] digest(String message) throws IOException {
        return digest(message.getBytes());
    }


}
