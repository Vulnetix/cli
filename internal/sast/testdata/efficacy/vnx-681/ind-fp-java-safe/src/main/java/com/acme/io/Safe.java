package com.acme.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Safe {
    int exact(File f) {
        return Math.toIntExact(f.length());
    }

    int viaPath(Path p) throws IOException {
        return Math.toIntExact(Files.size(p));
    }

    int count(List<String> names, String s) {
        int a = (int) names.size();
        int b = (int) s.length();
        long ms = System.currentTimeMillis();
        // int bad = (int) file.length();
        String doc = "(int) Files.size(p) is unsafe";
        return a + b;
    }
}
