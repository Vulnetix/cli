package com.acme.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class SafeUnzip {
    public void unzip(InputStream in, File dest) throws IOException {
        String destCanonical = dest.getCanonicalPath();
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File f = new File(dest, entry.getName());
                String cp = f.getCanonicalPath();
                if (!cp.startsWith(destCanonical + File.separator)) {
                    throw new IOException("Zip entry escapes target: " + entry.getName());
                }
                try (FileOutputStream fos = new FileOutputStream(f)) {
                    zis.transferTo(fos);
                }
            }
        }
    }
}
