package com.acme.jobs;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Importer {
    private static long imported = 0;

    public void run(List<String> rows) {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (String row : rows) {
            pool.submit(() -> {
                store(row);
~>                Importer.imported += 1;
            });
        }
        pool.shutdown();
    }

    private void store(String row) {
    }
}
