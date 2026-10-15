package com.acme.io;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Reader {
    public String first(Path p) {
        String line = null;
~>        try (BufferedReader r = Files.newBufferedReader(p)) { line = r.readLine(); } catch (IOException e) {}
        return line;
    }

    public void touch(Path p) {
        try {
            Files.createFile(p);
~>        } catch (IOException e) { e.getMessage(); }
    }
}
