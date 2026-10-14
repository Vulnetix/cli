package com.acme.util;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ConfigLoader {
    public Properties load(String name) throws Exception {
        File f = new File(System.getProperty("user.home"), name);
        Path p = Paths.get(name);
        try (FileInputStream in = new FileInputStream(f)) {
            return null;
        }
    }
}
