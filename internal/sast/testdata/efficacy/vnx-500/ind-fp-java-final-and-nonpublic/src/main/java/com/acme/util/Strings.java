package com.acme.util;

import java.util.Collections;
import java.util.List;

public final class Strings {
    public static final String EMPTY = "";
    public static final int MAX_LEN = 255;
    static final String SEP = ",";
    private static String cache;
    protected static int hits;

    public static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public static <T> List<T> listOf(T item) {
        return Collections.singletonList(item);
    }

    public static class Builder {
        private final StringBuilder sb = new StringBuilder();
    }
}
