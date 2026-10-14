package com.example.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;

public class Spool {
    private final File spoolDir;

    public Spool(File spoolDir) {
        this.spoolDir = spoolDir;
    }

    public File next() throws IOException {
        return File.createTempFile("job", ".dat", spoolDir);
    }

    public File restricted() throws IOException {
        File f = File.createTempFile("secret", ".key");
        Files.setPosixFilePermissions(f.toPath(), PosixFilePermissions.fromString("rw-------"));
        return f;
    }

    public File owner() throws IOException {
        File f = File.createTempFile("token", ".txt");
        f.setReadable(false, false);
        f.setReadable(true, true);
        return f;
    }

    public File relative(String name) {
        return new File("tmp/" + name);
    }
}
