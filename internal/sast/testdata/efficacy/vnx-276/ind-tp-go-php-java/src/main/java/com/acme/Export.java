package com.acme;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

public class Export {
    public void publish(Path out) throws IOException {
~>        Files.setPosixFilePermissions(out, PosixFilePermissions.fromString("rwxrwxrwx"));
    }
}
