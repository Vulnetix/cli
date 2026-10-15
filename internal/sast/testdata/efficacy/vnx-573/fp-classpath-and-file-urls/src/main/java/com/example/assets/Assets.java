package com.example.assets;

import java.io.File;
import java.io.InputStream;
import java.net.URL;

public class Assets {
    public InputStream logo() throws Exception {
        return getClass().getResource("/logo.png").openStream();
    }

    public InputStream template(String name) throws Exception {
        URL res = Assets.class.getClassLoader().getResource("templates/" + name);
        return res.openStream();
    }

    public InputStream local(File f) throws Exception {
        URL u = f.toURI().toURL();
        try (InputStream a = f.toURI().toURL().openStream()) {
            a.read();
        }
        return u.openStream();
    }
}
