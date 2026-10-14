package com.example.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.UUID;

public class SafeTemp {
    public Path file() throws IOException {
        return Files.createTempFile("report-", ".csv");
    }

    public Path dir() throws IOException {
        return Files.createTempDirectory("work",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    public java.io.File random() {
        return new java.io.File(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString());
    }
}
