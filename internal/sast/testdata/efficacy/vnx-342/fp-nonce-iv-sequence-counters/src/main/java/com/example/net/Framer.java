package com.example.net;

public class Framer {
    private long msgSeq = 0;
    private int jtiCounter = 0;
    private final byte[] iv = new byte[16];

    public Frame next(byte[] body) {
        msgSeq++;
        iv[15]++;
        String jti = String.valueOf(++jtiCounter);
        return new Frame(msgSeq, jti, body);
    }
}
