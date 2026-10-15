package com.acme.archive;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;

public class BundleExtractor {
    public void extract(InputStream raw, File outDir) throws Exception {
        try (ArchiveInputStream ais = new ArchiveStreamFactory()
                .createArchiveInputStream(new BufferedInputStream(raw))) {
            ArchiveEntry entry;
            while ((entry = ais.getNextEntry()) != null) {
~>                final File f = new File(outDir, entry.getName());
                if (entry.isDirectory()) {
                    f.mkdirs();
                    continue;
                }
                Files.copy(ais, f.toPath());
            }
        }
    }
}
