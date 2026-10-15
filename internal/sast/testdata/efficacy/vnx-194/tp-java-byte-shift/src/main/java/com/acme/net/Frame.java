package com.acme.net;

public final class Frame {
    public static int readLength(byte[] header) {
~>        return (header[0] << 8) | header[1];
    }

    public static int readInt(byte[] b, int off) {
~>        return (b[off] << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | b[off + 3];
    }
}
