package com.acme;

public final class Port {
    static int read(byte[] data, int off) {
        int[] widths = new int[4];
        widths[0] = widths[1] * 256 + widths[2];
        return (data[off] & 0xff) * 256 + (data[off + 1] & 0xff);
    }
}
