package com.acme;
import java.nio.file.*;
import java.nio.file.attribute.*;
public class Safe {
    Path make() throws Exception {
        FileAttribute<?> a = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
        return Files.createTempFile("report", ".csv", a);
    }
    Path dir() throws Exception { return Files.createTempDirectory("work"); }
}
