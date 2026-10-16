package com.acme;

import java.util.Objects;

public final class Ver implements Comparable<Ver> {
    private final int major;

    public Ver(int major) { this.major = major; }

    @Override
    public int compareTo(Ver o) { return Integer.compare(major, o.major); }

    @Override
    public boolean equals(Object o) {
        return o instanceof Ver v && v.major == major;
    }

    @Override
    public int hashCode() { return Objects.hash(major); }
}
