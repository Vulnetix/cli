package com.acme.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

public final class Exporter {

    public void publish(Path out, Path dir) throws IOException {
        Set<PosixFilePermission> perms = EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
~>                PosixFilePermission.OTHERS_WRITE);
        Files.setPosixFilePermissions(out, perms);
~>        Runtime.getRuntime().exec(new String[] {"chmod", "777", dir.toString()});
    }
}
