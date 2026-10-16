package com.acme.util;

public final class IdGenerator {
    private static int next = 0;
    private static String prefix;

    private IdGenerator() {
    }

    public static String nextId() {
        next++;
        prefix = "ID";
        return prefix + next;
    }
}
