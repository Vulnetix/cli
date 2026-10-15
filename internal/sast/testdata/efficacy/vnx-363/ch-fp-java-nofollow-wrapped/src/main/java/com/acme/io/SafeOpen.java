package com.acme.io;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;

public class SafeOpen {
    public SeekableByteChannel open(Path p) throws IOException {
        if (Files.isSymbolicLink(p)) {
            throw new IOException("link");
        }
        return Files.newByteChannel(p,
                EnumSet.of(StandardOpenOption.WRITE),
                LinkOption.NOFOLLOW_LINKS);
    }
}
