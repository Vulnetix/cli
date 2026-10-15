package com.acme.util;

public final class Flags {
    static final int MASK = 0x0F;

    static int low(int value) {
        return value & MASK;
    }

    static boolean both(Object a, Object b) {
        return (a != null) & (b != null);
    }

    static boolean other(Object a, Checker b) {
        return a != null & b.check();
    }

    static void accumulate(boolean[] seen, Object x) {
        seen[0] &= x != null;
    }
}
