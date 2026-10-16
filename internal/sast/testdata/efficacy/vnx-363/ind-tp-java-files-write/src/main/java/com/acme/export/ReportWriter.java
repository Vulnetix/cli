package com.acme.export;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReportWriter {
    public void write(Path target, String body) throws IOException {
        if (Files.isSymbolicLink(target)) {
            throw new IOException("refusing to write through a link: " + target);
        }
~>        try (BufferedWriter w = Files.newBufferedWriter(target, StandardCharsets.UTF_8)) {
            w.write(body);
        }
    }
}
