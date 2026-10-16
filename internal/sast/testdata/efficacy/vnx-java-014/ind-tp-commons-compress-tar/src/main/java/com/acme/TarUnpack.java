package com.acme;

import java.io.*;
import java.nio.file.*;
import org.apache.commons.compress.archivers.tar.*;

public class TarUnpack {
    public void unpack(InputStream in, Path dir) throws IOException {
        try (TarArchiveInputStream tin = new TarArchiveInputStream(in)) {
            TarArchiveEntry entry;
            while ((entry = tin.getNextTarEntry()) != null) {
~>                Path p = Paths.get(dir.toString(), entry.getName());
                Files.copy(tin, p, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
