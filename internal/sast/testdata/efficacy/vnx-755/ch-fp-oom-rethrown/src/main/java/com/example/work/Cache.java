package com.example.work;

public class Cache {
    private byte[] big;

    public void grow(int n) {
        try {
            big = new byte[n];
        } catch (OutOfMemoryError oom) {
            big = null;
            System.gc();
            throw oom;
        }
    }
}
