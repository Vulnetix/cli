package com.acme;

public final class Port {
    static int read(byte[] data, int off) {
~>        return data[off] * 256 + data[off + 1];
    }
}
