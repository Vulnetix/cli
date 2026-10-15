package com.acme;

import org.springframework.stereotype.Service;

@Service
public class HitCounter {
~>    private static long hits;

    public synchronized void reset() {
        hits = 0;
    }

    public void record() {
        hits++;
    }

    public long total() {
        return hits;
    }
}
