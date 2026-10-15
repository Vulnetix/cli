package com.acme;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class Safe {
    public void export(Path out, Path other, byte[] body) throws Exception {
        if (Files.isSymbolicLink(out)) {
            throw new SecurityException("link");
        }
        Files.write(other, body);
        try (var ch = Files.newByteChannel(out, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            ch.write(java.nio.ByteBuffer.wrap(body));
        }
    }
}
