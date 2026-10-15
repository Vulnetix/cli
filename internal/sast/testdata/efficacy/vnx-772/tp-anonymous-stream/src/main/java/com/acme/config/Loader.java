package com.acme.config;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.Scanner;

public class Loader {
    public Properties load(String path) throws Exception {
        Properties props = new Properties();
~>        props.load(new FileInputStream(path));
        return props;
    }

    public String slurp(String path) throws Exception {
~>        return new Scanner(new File(path)).useDelimiter("\\Z").next();
    }
}
