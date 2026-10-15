package com.example.config;

import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

public class Keys {
    public Properties load() throws Exception {
        Properties p = new Properties();
        p.load(Objects.requireNonNull(Keys.class.getResourceAsStream("/keys.properties"),
                "keys.properties missing from the classpath"));
        InputStream in = Objects.requireNonNull(getClass().getResourceAsStream("/other.properties"));
        p.load(in);
        return p;
    }
}
