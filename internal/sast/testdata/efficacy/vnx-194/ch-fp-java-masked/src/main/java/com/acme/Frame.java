package com.acme;

public class Frame {
    static int length(byte[] hdr) {
        int len = ((hdr[0] & 0xff) << 8) | (hdr[1] & 0xFF);
        return len;
    }
}
