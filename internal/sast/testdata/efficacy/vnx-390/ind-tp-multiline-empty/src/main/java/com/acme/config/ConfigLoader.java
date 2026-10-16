package com.acme.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class ConfigLoader {
    public Properties load(Path file) {
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            props.load(in);
~>        } catch (IOException e) {

        }
        return props;
    }

    public int port(Properties props) {
        int port = 8080;
        try {
            port = Integer.parseInt(props.getProperty("port"));
        }
~>        catch (NumberFormatException ex) {
        }
        return port;
    }
}
