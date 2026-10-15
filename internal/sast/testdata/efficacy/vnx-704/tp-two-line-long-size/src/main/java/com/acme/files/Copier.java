package com.acme.files;

import java.io.File;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;

public class Copier {
    public byte[] slurp(File source) {
        long size = source.length();
        log(size);
~>        return new byte[(int) size];
    }

    public int chunks(Path p, FileChannel ch) throws Exception {
        final long total = Files.size(p);
        long remaining = ch.size();
~>        int count = (int)total / 4096;
~>        return count + (int) remaining;
    }
}
