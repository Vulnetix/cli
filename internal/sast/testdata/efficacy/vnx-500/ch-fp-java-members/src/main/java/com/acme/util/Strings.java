package com.acme.util;

import java.util.List;

public final class Strings {
    public static final String EMPTY = "";
    public final static int SIZE = 4;
    @Deprecated public static final List<String> NAMES = List.of();

    public static <T> List<T> listOf(T first) {
        return List.of(first);
    }

    public static synchronized
            String join(List<String> parts,
                        String sep) {
        return String.join(sep, parts);
    }

    public static enum Kind { A, B }

    public static record Pair(String a, String b) { }

    public static abstract class Base { }

    public static native int nativeHash(byte[] data);
}
