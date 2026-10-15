package com.acme.plugins;

import java.io.File;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ArchiveInspector {
    public long totalSize(File archive) throws Exception {
        long total = 0;
        try (ZipFile zf = new ZipFile(archive)) {
            for (ZipEntry e : java.util.Collections.list(zf.entries())) {
                System.out.println("entry " + e.getName() + " size " + e.getSize());
                total += e.getSize();
            }
        }
        File report = new File(archive.getParentFile(), archive.getName() + ".txt");
        report.createNewFile();
        return total;
    }
}
