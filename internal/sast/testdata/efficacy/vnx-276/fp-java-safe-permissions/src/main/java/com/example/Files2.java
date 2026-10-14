package com.example;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

public class Files2 {
    public void write(Path p, File f) throws IOException {
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
        f.setWritable(true);
        f.setWritable(true, true);
        f.setReadable(true, false);
        new ProcessBuilder("chmod", "755", p.toString()).start();
    }
}
