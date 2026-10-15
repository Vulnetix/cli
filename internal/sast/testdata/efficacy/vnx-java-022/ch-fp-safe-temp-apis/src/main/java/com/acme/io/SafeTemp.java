package com.acme.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.UUID;

public class SafeTemp {
    private final File workDir;

    public SafeTemp(File workDir) {
        this.workDir = workDir;
    }

    public Path a() throws IOException {
        return Files.createTempFile("acme-", ".tmp");
    }

    public File b() throws IOException {
        return File.createTempFile("acme-", ".tmp", workDir);
    }

    public File c() {
        String tmp = System.getProperty("java.io.tmpdir");
        return new File(tmp, UUID.randomUUID() + ".part");
    }

    public File d() throws IOException {
        File f = File.createTempFile("acme-", ".key");
        Files.setPosixFilePermissions(f.toPath(), PosixFilePermissions.fromString("rw-------"));
        return f;
    }

    public Path e() throws IOException {
        return Files.createTempDirectory("acme-work");
    }
}
