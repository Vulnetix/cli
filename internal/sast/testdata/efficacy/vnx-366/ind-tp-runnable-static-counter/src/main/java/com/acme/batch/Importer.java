package com.acme.batch;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Importer {
    private static int imported = 0;
    private static long bytesRead = 0L;

    public static void importAll(List<String> files) {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (String f : files) {
            pool.submit(() -> {
                long n = readFile(f);
~>                bytesRead += n;
~>                imported++;
            });
        }
        pool.shutdown();
    }

    private static long readFile(String f) {
        return f.length();
    }
}
