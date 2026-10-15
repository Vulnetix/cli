package com.acme;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;

public class Csv {
    public String header(Path p) throws Exception {
        try (BufferedReader reader = Files.newBufferedReader(p)) {
            return reader.readLine();
        }
    }

    public java.io.InputStream open(Path p) throws Exception {
        java.io.InputStream in = Files.newInputStream(p);
        return in;
    }
}
