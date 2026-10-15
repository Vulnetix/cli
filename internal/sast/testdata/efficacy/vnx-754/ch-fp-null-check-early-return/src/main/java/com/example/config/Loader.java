package com.example.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Loader {
    public Properties load(String name) throws IOException {
        Properties props = new Properties();
        InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
        if (stream == null) {
            throw new IllegalStateException("missing resource " + name);
        }
        try (stream) {
            props.load(stream);
        }
        return props;
    }

    public boolean present(String name) {
        return getClass().getResource(name) != null;
    }
}
