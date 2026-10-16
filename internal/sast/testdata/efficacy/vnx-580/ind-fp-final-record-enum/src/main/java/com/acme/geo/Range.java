package com.acme.geo;

public record Range(int lo, int hi) implements Cloneable {
    @Override
    public Range clone() {
        return new Range(lo, hi);
    }
}
