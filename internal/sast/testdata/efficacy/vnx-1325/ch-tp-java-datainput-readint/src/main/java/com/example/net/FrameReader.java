package com.example.net;

import java.io.DataInputStream;
import java.io.IOException;

public class FrameReader {
    private final DataInputStream in;

    public FrameReader(DataInputStream in) {
        this.in = in;
    }

    public byte[] next() throws IOException {
        int length = in.readInt();
~>        byte[] frame = new byte[length];
        in.readFully(frame);
        return frame;
    }
}
