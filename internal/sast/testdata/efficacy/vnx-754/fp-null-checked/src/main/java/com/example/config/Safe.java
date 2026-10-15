package com.example.config;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URL;
import java.util.Objects;
import java.util.Properties;

public class Safe {
    public Properties read() throws Exception {
        Properties p = new Properties();
        InputStream in = Safe.class.getResourceAsStream("/app.properties");
        if (in == null) {
            throw new FileNotFoundException("app.properties not on classpath");
        }
        p.load(in);
        p.load(Objects.requireNonNull(getClass().getResourceAsStream("/more.properties"), "more.properties"));
        URL u = getClass().getResource("/x");
        if (u != null) {
            System.out.println(u.getPath());
        }
        InputStream opt = getClass().getResourceAsStream("/opt.properties");
        if (null != opt) {
            p.load(opt);
        }
        return p;
    }
}
