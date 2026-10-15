package com.acme.io;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class ReportWriter {
    public void write(Path out, byte[] body) throws IOException {
        if (Files.isSymbolicLink(out)) {
            throw new IOException("refusing to follow a link");
        }
~>        try (OutputStream os = Files.newOutputStream(
                out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            os.write(body);
        }
    }
}
