package com.example;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Set;

public class Setup {
    public void prepare(Path dir, File report, Path log) throws IOException {
~>        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxrwxrwx"));
~>        report.setWritable(true, false);
        Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ);
~>        perms.add(PosixFilePermission.OTHERS_WRITE);
        Files.setPosixFilePermissions(log, perms);
~>        Runtime.getRuntime().exec("chmod 777 " + dir);
    }
}
