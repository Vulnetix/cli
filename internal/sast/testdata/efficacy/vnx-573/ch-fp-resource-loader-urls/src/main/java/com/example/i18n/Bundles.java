package com.example.i18n;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.Properties;

public class Bundles {
    public Properties load(String name) throws IOException {
        Properties p = new Properties();
        URL res = Thread.currentThread().getContextClassLoader().getResource("i18n/" + name);
        try (InputStream in = res.openStream()) {
            p.load(in);
        }
        return p;
    }

    public Properties fromDisk(Path file) throws IOException {
        Properties p = new Properties();
        URL local = file.toUri().toURL();
        try (InputStream in = local.openStream()) {
            p.load(in);
        }
        try (InputStream in = Bundles.class.getResource("/defaults.properties").openStream()) {
            p.load(in);
        }
        return p;
    }
}
