package com.example.stats;

public class Histogram {
    int[] bins = new int[64];

    void reset(int n) {
~>        for (Integer i = 0; i < n; i++) {
            bins[i] = 0;
        }
~>        for (Long off = 0L; off < (long) n; off += 8) {
            bins[(int) (off % 64)]++;
        }
    }
}
