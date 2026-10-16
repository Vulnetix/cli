package com.acme;

import java.util.Properties;

public class FixtureTest {
    void load() throws Exception {
        Properties p = new Properties();
        p.load(FixtureTest.class.getResourceAsStream("/fixture.properties"));
        // getResourceAsStream("/x").read() is fine in a test
    }
}
