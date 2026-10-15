package com.shop;

import java.util.Properties;
import org.springframework.util.Assert;

public class Settings {
    String region(Properties props) {
        Object raw = props.getProperty("region");
        Assert.notNull(raw, "region");
        return raw.toString();
    }

    String home() {
        String home = System.getenv("HOME");
        assertNotNull(home);
        return home.trim();
    }
}
