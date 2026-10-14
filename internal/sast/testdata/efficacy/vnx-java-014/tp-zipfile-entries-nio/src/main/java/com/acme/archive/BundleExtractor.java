package com.acme.archive;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class BundleExtractor {
    public void extract(Path archive, Path target) throws Exception {
        try (ZipFile zip = new ZipFile(archive.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
~>                Path dest = target.resolve(e.getName());
                Files.copy(zip.getInputStream(e), dest, StandardCopyOption.REPLACE_EXISTING);
            }
            for (ZipEntry z : java.util.Collections.list(zip.entries())) {
~>                Path p = Paths.get(target.toString(),
                        z.getName());
                Files.createDirectories(p.getParent());
            }
        }
    }
}
