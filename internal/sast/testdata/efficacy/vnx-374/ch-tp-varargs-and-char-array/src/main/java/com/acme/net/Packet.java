package com.acme.net;

public final class Packet {
    private final byte[] payload;
    private char[] secret;

    public Packet(byte... payload) {
~>        this.payload = payload;
    }

    public void setSecret(char[] secret) {
~>        this.secret = secret;
    }

    public int length() {
        return payload.length;
    }
}
