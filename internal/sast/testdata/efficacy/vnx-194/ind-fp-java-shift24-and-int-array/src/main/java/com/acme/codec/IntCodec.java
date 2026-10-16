package com.acme.codec;

final class IntCodec {

    private IntCodec() {}

    static int readInt(byte[] b) {
        return (b[0] << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
    }

    static int pack(int[] words) {
        return (words[0] << 8) | words[1];
    }
}
