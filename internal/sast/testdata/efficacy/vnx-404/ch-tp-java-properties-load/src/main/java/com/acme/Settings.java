package com.acme;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Settings {
    public static Properties load(String path) throws IOException {
~>        FileInputStream in = new FileInputStream(path);
        Properties props = new Properties();
        props.load(in);
        return props;
    }
}
