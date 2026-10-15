package com.acme;

import java.io.*;
import java.util.Properties;

public class ConfigLoader {
    public Properties load(File file) throws IOException {
        Properties props = new Properties();
~>        FileInputStream in = new FileInputStream(file);
        props.load(in);
        return props;
    }

    public String firstLine(String path) throws IOException {
~>        BufferedReader reader = new BufferedReader(new FileReader(path));
        return reader.readLine();
    }

    public void append(String path, String text) throws IOException {
~>        final Writer w = new FileWriter(path, true);
        w.write(text);
        w.flush();
    }
}
