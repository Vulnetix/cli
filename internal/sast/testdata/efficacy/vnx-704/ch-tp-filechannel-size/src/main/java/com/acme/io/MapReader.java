package com.acme.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class MapReader {

    public ByteBuffer read(Path p) throws IOException {
        try (FileChannel in = FileChannel.open(p, StandardOpenOption.READ)) {
~>            ByteBuffer buf = ByteBuffer.allocate((int) in.size());
            in.read(buf);
            return buf;
        }
    }
}
