package com.example.boot;

import java.io.InputStream;
import java.net.URL;

public class Fetcher {
    static {
        System.setProperty("sun.net.client.defaultConnectTimeout", "5000");
        System.setProperty("sun.net.client.defaultReadTimeout", "10000");
    }

    public InputStream open(String link) throws Exception {
        return new URL(link).openStream();
    }
}
