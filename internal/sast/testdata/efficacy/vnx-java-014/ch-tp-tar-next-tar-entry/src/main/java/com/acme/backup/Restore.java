package com.acme.backup;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;

public class Restore {
    public void restore(InputStream raw, File dest) throws Exception {
        try (TarArchiveInputStream tis = new TarArchiveInputStream(raw)) {
            TarArchiveEntry entry;
            while ((entry = tis.getNextTarEntry()) != null) {
~>                File out = new File(dest, entry.getName());
                if (entry.isDirectory()) {
                    out.mkdirs();
                    continue;
                }
                try (OutputStream os = new FileOutputStream(out)) {
                    IOUtils.copy(tis, os);
                }
            }
        }
    }
}
