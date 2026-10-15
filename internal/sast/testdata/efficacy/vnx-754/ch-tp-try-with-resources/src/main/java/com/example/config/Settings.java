package com.example.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Settings {
    public static Properties load() throws IOException {
        Properties props = new Properties();
~>        try (InputStream is = Settings.class.getResourceAsStream("/settings.properties")) {
            props.load(is);
        }
        return props;
    }
}
