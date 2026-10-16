package org.example.util;

/**
 * Do not write: public static final int[] CODES = {1, 2, 3};
 * because callers can mutate the elements.
 */
public final class Codes {
    // public static final String[] LEGACY = {"a"};
    private static final int[] CODES = {1, 2, 3};

    public static final int[] codes() {
        return CODES.clone();
    }

    public static int[] copyOf(int[] src) {
        return src.clone();
    }

    public static final String HINT = "public static final String[] X = {}";
}
