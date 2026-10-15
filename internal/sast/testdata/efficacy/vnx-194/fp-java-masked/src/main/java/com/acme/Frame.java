package com.acme;

final class Frame {
    static int readLength(byte[] header) {
        return ((header[0] & 0xff) << 8) | (header[1] & 0xFF);
    }

    static int top(byte[] b) {
        return (b[0] << 24) | ((b[1] & 0xff) << 16);
    }

    static int checksum(int[] words) {
        return (words[0] << 16) | words[1];
    }

    static long mix(byte[] b) {
        return Byte.toUnsignedInt(b[0]) << 8 | Byte.toUnsignedInt(b[1]);
    }
}
