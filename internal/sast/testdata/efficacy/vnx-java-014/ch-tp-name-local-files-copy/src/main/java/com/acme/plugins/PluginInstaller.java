package com.acme.plugins;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class PluginInstaller {
    public void install(InputStream in, Path pluginDir) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                String name = ze.getName();
~>                Files.copy(zis, pluginDir.resolve(name), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
