package com.acme.plugins;

import java.io.File;
import java.nio.file.Files;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class PluginInstaller {
    public void install(JarFile jar, File pluginDir) throws Exception {
        for (JarEntry je : java.util.Collections.list(jar.entries())) {
            String name = je.getName();
            String rel = name.replace('\\', '/');
~>            File target = new File(pluginDir, rel);
            Files.copy(jar.getInputStream(je), target.toPath());
        }
    }
}
