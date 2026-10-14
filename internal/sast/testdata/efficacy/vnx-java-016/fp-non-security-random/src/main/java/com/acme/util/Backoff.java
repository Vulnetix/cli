package com.acme.util;

import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class Backoff {
    private final Random jitter = new Random();

    public long delayMillis(int attempt) {
        long base = 100L << attempt;
        return base + jitter.nextInt(50);
    }

    public void shuffle(List<String> servers) {
        Collections.shuffle(servers, new Random());
    }

    public String pickColor(String[] palette) {
        int idx = ThreadLocalRandom.current().nextInt(palette.length);
        double sample = Math.random();
        return palette[idx] + sample;
    }

    public int sampleSessionsForMetrics(int sessions) {
        int pct = jitter.nextInt(100);
        return pct < 5 ? sessions : 0;
    }
}
