package com.acme.feeds;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class BoundedFetcher {
    public byte[] fetch(String link) throws IOException {
        URL url = new URL(link);
        URLConnection conn = url.openConnection();
        conn.setConnectTimeout(5_000);
        conn.setReadTimeout(10_000);
        try (InputStream in = conn.getInputStream()) {
            return in.readAllBytes();
        }
    }
}
