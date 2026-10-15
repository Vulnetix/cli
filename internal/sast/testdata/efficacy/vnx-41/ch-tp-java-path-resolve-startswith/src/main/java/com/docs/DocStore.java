package com.docs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DocStore {
    private final Path base = Paths.get("/var/docs");

    public byte[] read(String name) throws IOException {
        Path requested = base.resolve(name);
~>        if (!requested.startsWith(base)) {
            throw new SecurityException("outside docs");
        }
        return Files.readAllBytes(requested);
    }

    public byte[] readOther(String name) throws IOException {
        java.io.File f = new java.io.File("/var/docs", name);
~>        if (!f.getAbsolutePath().startsWith("/var/docs")) {
            throw new SecurityException("outside docs");
        }
        return Files.readAllBytes(f.toPath());
    }
}
