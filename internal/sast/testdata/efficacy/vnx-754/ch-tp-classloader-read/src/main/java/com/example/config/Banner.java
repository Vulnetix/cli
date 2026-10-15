package com.example.config;

import java.io.IOException;
import java.io.InputStream;

public class Banner {
    public byte[] load() throws IOException {
~>        InputStream in = Banner.class.getClassLoader().getResourceAsStream("banner.txt");
        byte[] buf = new byte[4096];
        int n = in.read(buf);
        return java.util.Arrays.copyOf(buf, n);
    }
}
