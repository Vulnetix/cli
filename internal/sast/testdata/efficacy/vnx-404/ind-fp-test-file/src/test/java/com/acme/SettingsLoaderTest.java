package com.acme;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.FileInputStream;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class SettingsLoaderTest {

    @Test
    void loadsFixture() throws Exception {
        Properties p = new Properties();
        FileInputStream in = new FileInputStream("src/test/resources/app.properties");
        p.load(in);
        assertEquals("8080", p.getProperty("port"));
    }
}
