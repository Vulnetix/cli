package com.acme.net;

import java.io.IOException;
import java.net.URISyntaxException;

public class Fetcher {
    public byte[] fetch(String url) {
        byte[] out = new byte[0];
        try {
            out = Http.get(new java.net.URI(url));
~>        } catch (IOException | URISyntaxException e) {
        } finally {
            Http.release();
        }
        return out;
    }

    public void ping() {
        try {
            Http.ping();
~>        } catch (final Throwable t) {
        }
    }
}
