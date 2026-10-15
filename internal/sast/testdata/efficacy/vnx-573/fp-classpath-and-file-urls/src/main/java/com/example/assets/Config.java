package com.example.assets;

import java.io.InputStream;
import java.net.URL;

public class Config {
    public InputStream open() throws Exception {
        return new URL("file:///etc/app/app.conf").openStream();
    }
}
