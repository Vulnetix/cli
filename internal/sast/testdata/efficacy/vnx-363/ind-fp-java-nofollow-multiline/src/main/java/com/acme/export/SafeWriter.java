package com.acme.export;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class SafeWriter {
    public void write(Path target, byte[] body) throws IOException {
        if (Files.isSymbolicLink(target)) {
            throw new IOException("link");
        }
        try (OutputStream out = Files.newOutputStream(target,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                LinkOption.NOFOLLOW_LINKS)) {
            out.write(body);
        }
    }
}
