package com.example.model;

/**
 * Note: public boolean equals(Object o) must come with hashCode().
 */
public class Range {
    private final int lo;
    private final int hi;

    public Range(int lo, int hi) {
        this.lo = lo;
        this.hi = hi;
    }

    // public boolean equals(Object o) { ... } was removed on purpose
    public boolean sameBounds(Range other) {
        return lo == other.lo && hi == other.hi;
    }

    public int hashOf(Object o) {
        return o.hashCode();
    }
}
