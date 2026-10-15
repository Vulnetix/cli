package com.acme.docs;

public class Advice {
    public static final String BAD = "Do not write new Random(42) or rng.setSeed(1) for tokens";

    /*
     * new Random(seed) is reproducible.
     */
    public String text() {
        // r.setSeed(System.nanoTime());
        return BAD;
    }
}
