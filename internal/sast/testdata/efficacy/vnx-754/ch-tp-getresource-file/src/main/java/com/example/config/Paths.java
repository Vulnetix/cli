package com.example.config;

import java.io.File;
import java.net.URISyntaxException;

public class Paths {
    public File schema() {
~>        return new File(Paths.class.getResource("/schema.json").getFile());
    }

    public java.nio.file.Path fixtures() throws URISyntaxException {
~>        return java.nio.file.Paths.get(getClass().getResource("/fixtures").toURI());
    }
}
