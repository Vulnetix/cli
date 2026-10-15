package com.acme.archive;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class FlatExtractor {
    public void flatten(InputStream in, File dest) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = new File(entry.getName()).getName();
                File out = new File(dest, name);
                Path alt = dest.toPath().resolve(Paths.get(entry.getName()).getFileName().toString());
                Files.copy(zis, out.toPath());
                System.out.println(alt);
            }
        }
    }
}
