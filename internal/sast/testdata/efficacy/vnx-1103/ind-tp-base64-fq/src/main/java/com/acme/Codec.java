package com.acme;

public class Codec {
    public byte[] decode(String s) throws java.io.IOException {
~>        return new sun.misc.BASE64Decoder().decodeBuffer(s);
    }
}
