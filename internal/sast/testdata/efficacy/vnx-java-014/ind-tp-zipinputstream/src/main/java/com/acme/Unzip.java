package com.acme;

import java.io.*;
import java.util.zip.*;

public class Unzip {
    public void extract(InputStream in, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
~>                File out = new File(destDir, entry.getName());
                if (entry.isDirectory()) { out.mkdirs(); continue; }
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    zis.transferTo(fos);
                }
            }
        }
    }
}
