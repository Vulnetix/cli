package com.acme;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Properties;

public class ConfigLoader {
    public Properties load(String file) throws Exception {
        Properties props = new Properties();
~>        BufferedReader reader =
                new BufferedReader(new FileReader(file));
        props.load(reader);
        reader.close();
        return props;
    }
}
