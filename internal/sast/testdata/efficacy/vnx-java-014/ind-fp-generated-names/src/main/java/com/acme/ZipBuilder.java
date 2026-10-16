package com.acme;

import java.io.*;
import java.util.zip.*;

public class ZipBuilder {
    public void write(File dir, File outZip) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outZip))) {
            for (File f : dir.listFiles()) {
                zos.putNextEntry(new ZipEntry(f.getName()));
                try (FileInputStream in = new FileInputStream(new File(dir, f.getName()))) {
                    in.transferTo(zos);
                }
                zos.closeEntry();
            }
        }
    }
}
