package com.acme.util;

import java.util.Collections;
import java.util.List;

public final class Constants {
    private static final int[] PRIMES = {2, 3, 5, 7};
    protected static final String[] NAMES = {"x"};
    public static final int[] EMPTY = new int[0];
    public static final String[] NONE = {};
    public static final Object[] NOTHING = new Object[] {};
    public static final List<String> SCHEMES = Collections.unmodifiableList(List.of("http", "https"));
    public static final String DEFAULT = "x";
    public static int[] scratch = new int[4];
    public final int[] buffer = new int[8];

    public static final int[] copyPrimes() {
        return PRIMES.clone();
    }
}
