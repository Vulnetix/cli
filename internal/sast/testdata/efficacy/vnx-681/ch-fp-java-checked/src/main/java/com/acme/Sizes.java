package com.acme;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Sizes {
    int count(Path p, List<String> items) throws Exception {
        long size = Files.size(p);
        int exact = Math.toIntExact(Files.size(p));
        int n = items.size();
        long started = System.currentTimeMillis();
        return exact + n + (int) (size % 10) + (int) started % 2;
    }
}
