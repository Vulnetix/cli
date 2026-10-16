package com.acme;
import java.io.*;
import java.util.Properties;
public class Loader {
    public Properties load(File f) {
        Properties p = new Properties();
        try (InputStream in = new FileInputStream(f)) {
            p.load(in);
~>        } catch (IOException e) {}
        return p;
    }
}
