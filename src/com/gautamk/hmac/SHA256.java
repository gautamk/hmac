package com.gautamk.hmac;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Created by gautam on 11/14/15.
 */
public class SHA256 {
    /**
     * Initial K values. These are the first 32
     * bits of the fractional parts of the cube root
     * of the first 64 primes.
     */
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /**
     * Initial H values. These are the first 32
     * bits of the fractional parts of the square
     * roots of the first eight primes.
     */
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
    private static byte[] applyPadding(byte[] message) {
        int length = message.length;
        int tail = length % 64; // 64 bytes = 512 bits
        int padding;

        // Make sure there's space for appending message length
        if ((64 - tail >= 9)) {
            padding = 64 - tail;
        } else {
            padding = 128 - tail;
        }

        byte[] pad = new byte[padding];
        pad[0] = (byte) 0x80; // 0x80 == 1000000, i.e append 1
        long messageLengthBits = length * 8;
        for (int i = 0; i < 8; i++) {
            // Append message length in the last byte followed by zeros s
            // messageLengthBits >>> 8 = 0
            pad[pad.length - 1 - i] = (byte) ((messageLengthBits >>> (8 * i)) & 0xFF);
        }

        byte[] result = new byte[length + padding];
        System.arraycopy(message, 0, result, 0, length);
        System.arraycopy(pad, 0, result, length, pad.length);

        return result;
    }

    /**
     * Ch(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z)
     *
     * @param X
     * @param Y
     * @param Z
     * @return
     */
    private static int Ch(int X, int Y, int Z) {
        // (X AND Y) XOR (Complement X AND Z)
        return (X & Y) ^ (~X & Z);
    }

    /**
     * Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
     *
     * @param X
     * @param Y
     * @param Z
     * @return
     */
    private static int Maj(int X, int Y, int Z) {
        // (X AND Y) XOR (X AND Z) XOR (Y AND Z)
        return (X & Y) ^ (X & Z) ^ (Y & Z);
    }

    /**
     * Implements Σ0
     * RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22),
     *
     * @param X
     * @return
     */
    private static int uSigma0(int X) {
        return Integer.rotateRight(X, 2)
                ^ Integer.rotateRight(X, 13)
                ^ Integer.rotateRight(X, 22);
    }

    /**
     * Implements Σ1
     * RotR(X, 6) ⊕ RotR(X, 11) ⊕ RotR(X, 25),
     *
     * @param X
     * @return
     */
    private static int uSigma1(int X) {
        return Integer.rotateRight(X, 6)
                ^ Integer.rotateRight(X, 11)
                ^ Integer.rotateRight(X, 25);
    }

    /**
     * σ0 (X) = RotR(X, 7) ⊕ RotR(X, 18) ⊕ ShR(X, 3),
     *
     * @param X
     * @return
     */
    private static int lSigma0(int X) {
        return Integer.rotateRight(X, 7)
                ^ Integer.rotateRight(X, 18)
                ^ X >>> 3;
    }

    /**
     * σ1 (X) = RotR(X, 17) ⊕ RotR(X, 19) ⊕ ShR(X, 10),
     *
     * @param X
     * @return
     */
    private static int lSigma1(int X) {
        return Integer.rotateRight(X, 17)
                ^ Integer.rotateRight(X, 19)
                ^ X >>> 10;
    }

    public static byte[] digest(byte[] message) {
        byte[] paddedMessage = applyPadding(message);
        BitIterator512 bitIterator512 = new BitIterator512(paddedMessage);

        // Initialize registers
        int[] h = Arrays.copyOf(H, H.length);

        while (bitIterator512.hasNext()) {
            byte[] next = bitIterator512.next();

        }
        return message;
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


class BitIterator512 implements Iterator<byte[]> {
    private final byte[] bytes;
    private int position = 0;

    public BitIterator512(byte[] bytes) {
        this.bytes = bytes;

    }

    @Override
    public boolean hasNext() {
        return position < bytes.length;
    }


    @Override
    public byte[] next() {
        if (hasNext()) {
            byte[] next = Arrays.copyOfRange(this.bytes, position, position + 64);// 64 bytes = 512 bits
            position += 64;
            return next;
        } else {
            throw new NoSuchElementException();
        }
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException();
    }
}