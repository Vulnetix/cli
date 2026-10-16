package com.acme.util;

import java.util.List;

public class Buffers {
    private byte[] data;
    private char[] name;
    private List<String> tags;
    public int[] exposed;

    public byte[] read(int n) {
        byte[] data = new byte[n];
        fill(data);
        return data;
    }

    public char[] rename(char[] name) {
        return name;
    }

    byte[] rawData() {
        return data;
    }

    protected char[] rawName() {
        return name;
    }

    private byte[] internal() {
        return data;
    }

    public List<String> getTags() {
        return tags;
    }

    public int[] getExposed() {
        return exposed;
    }

    // public byte[] getData() { return data; }
}
