package com.acme.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class PluginInstaller {
    public void install(File zip, String destination) throws IOException {
        try (ZipFile zf = new ZipFile(zip)) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                String name = ze.getName();
~>                try (FileOutputStream fos = new FileOutputStream(destination + File.separator + name);
                     InputStream is = zf.getInputStream(ze)) {
                    is.transferTo(fos);
                }
            }
        }
    }
}
