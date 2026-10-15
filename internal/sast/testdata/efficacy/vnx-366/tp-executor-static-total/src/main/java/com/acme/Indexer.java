package com.acme;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Indexer {
    public static int indexed;

    public void indexAll(String[] docs) {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (String d : docs) {
            pool.submit(() -> {
                index(d);
~>                Indexer.indexed++;
            });
        }
        pool.shutdown();
    }

    private void index(String d) {
    }
}
