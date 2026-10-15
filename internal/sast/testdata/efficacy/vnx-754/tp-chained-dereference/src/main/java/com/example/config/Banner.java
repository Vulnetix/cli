package com.example.config;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Banner {
    public byte[] load() throws IOException {
~>        return Banner.class.getResourceAsStream("/banner.txt").readAllBytes();
    }

    public Path schemaDir() throws URISyntaxException {
~>        return Paths.get(getClass().getResource("/schema").toURI());
    }

    public String templatePath() {
~>        return Thread.currentThread().getContextClassLoader().getResource("tpl/main.html").getFile();
    }
}
