package com.acme.archive;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class Lister {
    public List<String> list(File archive) throws Exception {
        List<String> names = new ArrayList<>();
        try (ZipFile zip = new ZipFile(archive)) {
            for (ZipEntry e : java.util.Collections.list(zip.entries())) {
                names.add(e.getName());
                System.out.println("entry " + e.getName() + " size " + e.getSize());
            }
        }
        File report = new File(archive.getParentFile(), "listing.txt");
        return names;
    }
}
