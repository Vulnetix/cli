package com.acme;

public class Range<T extends Comparable<T>>
        implements Comparable<Range<T>> {
    private final T low;

    Range(T low) {
        this.low = low;
    }

~>    @Override public int compareTo(final Range<T> o) {
        return low.compareTo(o.low);
    }
}
