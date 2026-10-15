package com.acme.kdf;

public class Holder {
    private String name;
    private byte[] data;

    public String getName() { return name; }

    public int size() { return data.length; }

    public byte[] encoded() {
        String data = "x";
        return data.getBytes();
    }
}
