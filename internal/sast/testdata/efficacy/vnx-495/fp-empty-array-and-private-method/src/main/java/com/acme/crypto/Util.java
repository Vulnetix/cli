package com.acme.crypto;

public class Util {
    private static final String[] EMPTY = new String[0];
    private static final int[] NONE = {};
    private byte[] buffer;

    public String[] none() {
        return EMPTY;
    }

    public int[] nothing() {
        return NONE;
    }

    private byte[] raw() {
        return buffer;
    }

    byte[] pkg() {
        return buffer;
    }
}
