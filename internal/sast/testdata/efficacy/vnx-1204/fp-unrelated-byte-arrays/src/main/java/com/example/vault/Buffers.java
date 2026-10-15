package com.example.vault;

import java.util.Random;

public class Buffers {
    // new IvParameterSpec(new byte[16]) is what we must never do.
    private static final byte[] MAGIC = { 0x50, 0x4b, 0x03, 0x04 };
    private final Random jitter = new Random();

    byte[] read(java.io.InputStream in) throws Exception {
        byte[] buf = new byte[16];
        in.read(buf);
        byte[] padding = new byte[16];
        jitter.nextBytes(padding);
        String doc = "new IvParameterSpec(new byte[16])";
        return buf;
    }
}
