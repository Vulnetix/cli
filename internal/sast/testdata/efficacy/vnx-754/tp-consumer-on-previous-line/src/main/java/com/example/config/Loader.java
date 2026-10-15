package com.example.config;

import java.util.Properties;

public class Loader {
    public Properties read() throws Exception {
        Properties p = new Properties();
        p.load(
~>                this.getClass().getClassLoader().getResourceAsStream("defaults.properties"));
        return p;
    }
}
