package com.acme.proto;

import java.io.DataInputStream;
import java.io.IOException;

public final class FrameDecoder {

    private final DataInputStream in;

    public FrameDecoder(DataInputStream in) {
        this.in = in;
    }

    public byte[] readFrame() throws IOException {
        byte[] hdr = new byte[4];
        in.readFully(hdr);
~>        int length = (hdr[2] << 8) | hdr[3];
        byte[] body = new byte[length];
        in.readFully(body);
        return body;
    }
}
