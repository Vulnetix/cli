package com.acme.util;

public final class Arrays2 {
    public static final String[] copyOf(String[] in) {
        return in.clone();
    }

    public static final int[] range(int n) {
        int[] out = new int[n];
        for (int i = 0; i < n; i++) out[i] = i;
        return out;
    }

    public static final String TYPE_NAME = "String[]";
}
