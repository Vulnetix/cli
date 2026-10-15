package com.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Loader {
    public Properties load(String file) throws IOException {
        Properties props = new Properties();
        FileInputStream in = new FileInputStream(file);
        try {
            props.load(in);
        } finally {
            in.close();
        }
        return props;
    }

    public FileInputStream open(String file) throws IOException {
        FileInputStream in = new FileInputStream(file);
        return in;
    }
}
