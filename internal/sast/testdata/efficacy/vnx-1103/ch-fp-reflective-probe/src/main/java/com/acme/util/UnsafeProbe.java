package com.acme.util;

import java.lang.reflect.Field;

public final class UnsafeProbe {
    private static final String UNSAFE_CLASS = "sun.misc.Unsafe";
    private static final String INTERNAL = "jdk.internal.misc.Unsafe";

    public static boolean available() {
        try {
            Class<?> c = Class.forName(UNSAFE_CLASS);
            Field f = c.getDeclaredField("theUnsafe");
            return f != null;
        } catch (ReflectiveOperationException e) {
            return false;
        }
    }

    /** Falls back when sun.misc.Unsafe is missing on the running JDK. */
    public static String reason() {
        return "no " + INTERNAL;
    }
}
