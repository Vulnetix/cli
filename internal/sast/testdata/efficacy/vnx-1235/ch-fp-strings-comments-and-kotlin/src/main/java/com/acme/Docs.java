package com.acme;

public class Docs {
    // Avoid: for (Integer i = 0; i < n; i++) { sum += i; }
    static final String BAD = "Long sum = 0L; for (;;) { sum += 1; }";

    int fine(int n) {
        long sum = 0L;
        for (int i = 0; i < n; i++) {
            sum += i;
        }
        return (int) sum;
    }
}
