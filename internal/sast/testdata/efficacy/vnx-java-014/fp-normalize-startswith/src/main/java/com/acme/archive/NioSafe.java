package com.acme.archive;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class NioSafe {
    public void extract(ZipInputStream zis, Path target) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            Path resolved = target.resolve(entry.getName()).normalize();
            if (!resolved.startsWith(target)) {
                throw new SecurityException("zip slip: " + entry.getName());
            }
            Files.copy(zis, resolved);
        }
        ZipEntry next = zis.getNextEntry();
        if (next != null && next.getName().contains("..")) {
            throw new SecurityException("bad entry");
        }
    }
}
