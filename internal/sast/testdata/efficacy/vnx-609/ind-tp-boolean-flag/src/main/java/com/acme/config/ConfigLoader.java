package com.acme.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Properties;

public class ConfigLoader {

    private boolean initialized;
    private final Properties props = new Properties();

    public String get(String key) {
        ensureLoaded();
        return props.getProperty(key);
    }

    private void ensureLoaded() {
        if (!initialized) {
~>            synchronized (this) {
                if (!initialized) {
                    try (InputStream in = getClass().getResourceAsStream("/app.properties")) {
                        props.load(in);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                    initialized = true;
                }
            }
        }
    }
}
