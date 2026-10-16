package com.acme;

import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

public class Checked {
    Properties a() throws Exception {
        InputStream in = Objects.requireNonNull(
            getClass().getResourceAsStream("/a.properties"), "a.properties missing");
        Properties p = new Properties();
        p.load(in);
        return p;
    }

    Properties b() throws Exception {
        InputStream in = Checked.class.getResourceAsStream("/b.properties");
        if (in == null) {
            throw new IllegalStateException("b.properties missing");
        }
        Properties p = new Properties();
        p.load(in);
        return p;
    }
}
