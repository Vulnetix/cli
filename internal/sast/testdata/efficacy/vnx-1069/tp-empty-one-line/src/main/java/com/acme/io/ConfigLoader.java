package com.acme.io;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class ConfigLoader {
    public Properties load(String path) {
        Properties p = new Properties();
        try (FileInputStream in = new FileInputStream(path)) {
            p.load(in);
~>        } catch (IOException e) {}
        return p;
    }

    public int parse(String s) {
        try {
            return Integer.parseInt(s);
~>        } catch(NumberFormatException ex) { }
        return 0;
    }
}
