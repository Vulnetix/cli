package com.acme.proto;

final class FrameDecoder {

    private FrameDecoder() {}

    static int length(byte[] hdr) {
        return ((hdr[2] & 0xff) << 8) | (hdr[3] & 0xff);
    }

    static int port(byte[] p) {
        return Byte.toUnsignedInt(p[0]) * 256 + Byte.toUnsignedInt(p[1]);
    }
}
