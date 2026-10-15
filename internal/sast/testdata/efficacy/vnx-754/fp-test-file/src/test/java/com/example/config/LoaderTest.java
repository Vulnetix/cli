package com.example.config;

import java.util.Properties;

public class LoaderTest {
    void loads() throws Exception {
        new Properties().load(getClass().getResourceAsStream("/test.properties"));
    }
}
