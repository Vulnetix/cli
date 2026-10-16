package com.acme.files;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ArchiveStore {

    private final Path base = Paths.get("/var/lib/archive");

    public InputStream open(String entryName) throws IOException {
        Path target = base.resolve(entryName);
~>        if (!target.startsWith(base)) {
            throw new SecurityException("entry outside archive: " + entryName);
        }
        return Files.newInputStream(target);
    }
}
