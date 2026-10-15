package com.acme;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;

public class Csv {
    public String header(Path p) throws Exception {
~>        BufferedReader reader = Files.newBufferedReader(p);
        return reader.readLine();
    }
}
