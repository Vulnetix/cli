package com.acme.geo;

import com.google.common.io.Resources;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class GeoLookup {
    public String lookup(String ip) throws IOException {
        URL api = new URL("https://geo.example.net/v1/" + ip);
~>        return Resources.toString(api, StandardCharsets.UTF_8);
    }
}
