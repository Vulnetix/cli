package com.acme.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

public class SafeLoader {
    public byte[] read(File file) {
        return new byte[Math.toIntExact(file.length())];
    }

    public byte[] limited(Path p) throws Exception {
        long size = Files.size(p);
        if (size > Integer.MAX_VALUE) {
            throw new IllegalStateException("too large");
        }
        return new byte[(int) size];
    }

    public byte[] capped(File f) {
        long n = f.length();
        if (n > MAX_UPLOAD) {
            throw new IllegalArgumentException();
        }
        return new byte[(int) n];
    }

    private static final long MAX_UPLOAD = 1 << 20;
}
