package com.acme.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class Zipper {
    public void zip(File[] files, File target) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(target))) {
            for (File file : files) {
                ZipEntry entry = new ZipEntry(file.getName());
                zos.putNextEntry(entry);
                Files.copy(file.toPath(), zos);
                zos.closeEntry();
                System.out.println("added " + entry.getName() + " -> " + new File(target.getParentFile(), "manifest.txt"));
            }
        }
    }
}
