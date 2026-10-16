package com.acme;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Safe {
    byte[] a(File file) { return new byte[Math.toIntExact(file.length())]; }

    byte[] b(Path p) throws IOException {
        long size = Files.size(p);
        if (size > Integer.MAX_VALUE) {
            throw new IllegalStateException("too large");
        }
        return new byte[(int) size];
    }
}
