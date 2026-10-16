package com.acme.io;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class ConfigLoader {
    public Properties load(String file) {
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(file)) {
            props.load(in);
        } catch (IOException e) {

        }
        return props;
    }

    public void save(Properties props, String file) {
        try {
            props.store(new java.io.FileOutputStream(file), null);
        } catch (IOException e) {
            e.toString();
        }
    }

    public int port(Properties props) {
        try {
            return Integer.parseInt(props.getProperty("port"));
~>        } catch (NumberFormatException e) {
            // TODO
        }
        return 8080;
    }
}
