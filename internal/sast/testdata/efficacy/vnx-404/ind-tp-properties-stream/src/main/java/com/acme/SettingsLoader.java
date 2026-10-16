package com.acme;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class SettingsLoader {
    private final File baseDir;

    public SettingsLoader(File baseDir) {
        this.baseDir = baseDir;
    }

    public Properties load(String name) throws IOException {
        File file = new File(baseDir, name + ".properties");
        Properties props = new Properties();
~>        FileInputStream in = new FileInputStream(file);
        props.load(in);
        return props;
    }
}
