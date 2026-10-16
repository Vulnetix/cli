package com.acme.feeds;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class FeedFetcher {
    public String fetch(String link) throws IOException {
~>        try (InputStream in = new URL(link).openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
