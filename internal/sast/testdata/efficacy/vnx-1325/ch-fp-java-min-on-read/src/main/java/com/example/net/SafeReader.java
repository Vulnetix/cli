package com.example.net;

import java.io.DataInputStream;
import java.io.IOException;

public class SafeReader {
    private static final int MAX_FRAME = 1 << 16;

    public byte[] next(DataInputStream in) throws IOException {
        int length = Math.min(in.readInt(), MAX_FRAME);
        byte[] frame = new byte[length];
        in.readFully(frame);
        return frame;
    }
}
