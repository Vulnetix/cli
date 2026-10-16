package com.acme;

public class Docs {
    // do not write a.compareTo(b) == 1 or x.equals(null) or r == Double.NaN
    static final String HINT = "if (a.compareTo(b) == 1) { } r != Double.NaN";

    /** Avoid {@code c.equals(null)}. */
    boolean isNull(Object c) { return c == null; }
}
