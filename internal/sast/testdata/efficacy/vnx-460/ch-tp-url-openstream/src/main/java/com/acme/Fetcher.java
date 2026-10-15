package com.acme;

import java.io.InputStream;
import java.net.URL;

public class Fetcher {
    public byte[] fetch(String address) throws Exception {
~>        InputStream in = new URL(address).openStream();
        byte[] body = in.readAllBytes();
        in.close();
        return body;
    }
}
