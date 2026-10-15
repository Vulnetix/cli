package com.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Loader {
    public Properties load(String file) throws IOException {
        Properties props = new Properties();
~>        FileInputStream in = new FileInputStream(file);
        props.load(in);
        in.close();
        return props;
    }
}
