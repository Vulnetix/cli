package com.acme;

import java.io.IOException;
import java.util.Properties;

public class Settings {
    public Properties read() throws IOException {
        Properties props = new Properties();
~>        props.load(Settings.class.getClassLoader().getResourceAsStream("app.properties"));
        return props;
    }
}
