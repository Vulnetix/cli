package com.acme.jobs;

public class Importer {
    private final int batchSize = 250;

    public void run() {
        final int limit = 250;
        for (int i = 0; i < limit; i++) {
            step(i);
        }
    }

    private void step(int i) {
    }
}
