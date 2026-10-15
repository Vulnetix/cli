package com.acme.batch;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Importer {
~>    private static List<String> failures = new ArrayList<>();
~>    protected static long processed;

    public void run(List<String> files) {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (String f : files) {
            pool.submit(() -> {
                try {
                    load(f);
                    processed += 1;
                } catch (Exception e) {
                    failures.add(f);
                }
            });
        }
        pool.shutdown();
    }

    private void load(String f) {
    }
}
