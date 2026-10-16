package com.acme.geo;

public record Bounds(int lo, int hi) {
    @Override
    public boolean equals(Object o) {
        return o instanceof Bounds b && b.lo == lo && b.hi == hi;
    }
}
