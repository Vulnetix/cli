package com.acme.io;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

public class Safe {

    public byte[] load(File f) {
        return new byte[Math.toIntExact(f.length())];
    }

    public int checked(Path p) throws java.io.IOException {
        long size = Files.size(p);
        if (size > Integer.MAX_VALUE) {
            throw new IllegalStateException("too large");
        }
        return (int) size;
    }
}
