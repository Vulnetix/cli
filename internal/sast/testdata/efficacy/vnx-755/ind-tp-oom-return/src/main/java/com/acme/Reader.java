package com.acme;

public class Reader {
    public byte[] read(int n) {
        try {
            return new byte[n];
~>        } catch (OutOfMemoryError oom) {
            return new byte[0];
        }
    }
}
