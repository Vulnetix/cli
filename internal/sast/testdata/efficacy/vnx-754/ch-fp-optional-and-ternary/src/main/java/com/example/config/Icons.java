package com.example.config;

import java.io.InputStream;
import java.net.URL;
import java.util.Optional;

public class Icons {
    public Optional<InputStream> icon(String name) {
        return Optional.ofNullable(getClass().getResourceAsStream("/icons/" + name));
    }

    public String where(String name) {
        URL u = getClass().getResource(name);
        return u == null ? "missing" : u.toExternalForm();
    }
}
