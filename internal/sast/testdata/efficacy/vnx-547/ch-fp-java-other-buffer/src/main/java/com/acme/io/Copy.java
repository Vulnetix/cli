package com.acme.io;

import java.io.IOException;
import java.io.InputStream;

public class Copy {
    private static final int CHUNK = 4096;

    public int pump(InputStream in, byte[] dst) throws IOException {
        byte[] scratch = new byte[CHUNK];
        int a = in.read(scratch, 0, scratch.length);
        return a + in.read(dst, 0, 4096);
    }
}
