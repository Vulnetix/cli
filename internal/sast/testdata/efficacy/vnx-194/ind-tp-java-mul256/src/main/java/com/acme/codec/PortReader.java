package com.acme.codec;

final class PortReader {

    private PortReader() {}

    static int port(byte[] packet, int offset) {
~>        return packet[offset] * 256 + packet[offset + 1];
    }
}
