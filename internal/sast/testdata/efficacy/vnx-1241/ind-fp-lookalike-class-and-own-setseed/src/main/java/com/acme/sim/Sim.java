package com.acme.sim;

public class Sim {
    private long seed;

    public void setSeed(long s) {
        this.seed = s;
    }

    public void reset() {
        setSeed(7L);
        PseudoRandomSource src = new PseudoRandomSource(99L);
        src.advance();
    }

    // Do not write new Random(12345) for tokens
    static final String NOTE = "new Random(1234)";
}
