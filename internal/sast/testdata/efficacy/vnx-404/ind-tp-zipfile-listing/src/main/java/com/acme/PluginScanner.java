package com.acme;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class PluginScanner {

    public List<String> classNames(File jar) throws IOException {
        List<String> names = new ArrayList<>();
~>        ZipFile zip = new ZipFile(jar);
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            String n = entries.nextElement().getName();
            if (n.endsWith(".class")) {
                names.add(n.replace('/', '.').substring(0, n.length() - 6));
            }
        }
        return names;
    }
}
