package com.acme.plugins;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class SafeUnzip {
    public void unzip(ZipInputStream zis, File destDir) throws IOException {
        Path destPath = destDir.toPath().toAbsolutePath().normalize();
        ZipEntry entry = zis.getNextEntry();
        while (entry != null) {
            File outFile = new File(destDir, entry.getName());
            if (!outFile.toPath().toAbsolutePath().normalize().startsWith(destPath)) {
                throw new IOException("Entry is outside of the target dir: " + entry.getName());
            }
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                zis.transferTo(fos);
            }
            entry = zis.getNextEntry();
        }
    }
}
