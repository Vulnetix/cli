package com.acme;

public final class Range<T extends Comparable<T>>
        implements Comparable<Range<T>> {
    private final T lo;
    private final T hi;

    public Range(T lo, T hi) {
        this.lo = lo;
        this.hi = hi;
    }

~>    @Override public int compareTo(Range<T> o) {
        int c = lo.compareTo(o.lo);
        return c != 0 ? c : hi.compareTo(o.hi);
    }
}
