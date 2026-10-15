package com.acme.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

public class Reader {

    public ByteBuffer read(Path p) throws IOException {
        long size = Files.size(p);
~>        ByteBuffer buf = ByteBuffer.allocate((int) size);
        return buf;
    }
}
