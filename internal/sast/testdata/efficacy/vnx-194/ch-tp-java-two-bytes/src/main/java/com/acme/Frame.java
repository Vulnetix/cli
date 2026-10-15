package com.acme;

public class Frame {
    static int length(byte[] hdr) {
~>        int len = (hdr[0] << 8) | hdr[1];
        return len;
    }
}
