package com.acme.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Optional {
    public String overrides(Path p) {
        try {
            return Files.readString(p);
        } catch (IOException e) {
            // optional file, defaults apply
        }
        return "";
    }

    public int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException ignored) {}
        return 0;
    }

    public void close(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception expected) {
        }
    }

    public void drain(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception unused) {
            /* best effort */
        }
    }
}
