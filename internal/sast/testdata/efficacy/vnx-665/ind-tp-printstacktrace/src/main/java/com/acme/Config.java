package com.acme;

import java.io.FileInputStream;
import java.util.Properties;

public class Config {
    static final Properties PROPS = new Properties();

    static {
        try (FileInputStream in = new FileInputStream("/etc/acme/app.properties")) {
            PROPS.load(in);
~>        } catch (java.io.IOException e) {
            e.printStackTrace();
        }
    }
}
