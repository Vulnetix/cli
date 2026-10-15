package com.acme.util;

public class Holder {
    // public static final int[] LEGACY = {1, 2}; removed in 2.0
    private final String doc = "public static final int[] X = {1};";

    public static int[] make() {
        final int[] local = {1, 2, 3};
        return local.clone();
    }
}
