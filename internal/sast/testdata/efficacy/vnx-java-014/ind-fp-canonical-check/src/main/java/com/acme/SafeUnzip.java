package com.acme;

import java.io.*;
import java.util.zip.*;

public class SafeUnzip {
    public void extract(InputStream in, File destDir) throws IOException {
        String root = destDir.getCanonicalPath() + File.separator;
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File out = new File(destDir, entry.getName());
                if (!out.getCanonicalPath().startsWith(root)) {
                    throw new IOException("Zip entry outside target: " + entry.getName());
                }
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    zis.transferTo(fos);
                }
            }
        }
    }
}
