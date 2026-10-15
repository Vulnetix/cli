package com.acme.offheap;

import java.lang.reflect.Field;
~>import sun.misc.Unsafe;

public final class Memory {
    private static final Unsafe UNSAFE;

    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            UNSAFE = (Unsafe) f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static long allocate(long bytes) {
        return UNSAFE.allocateMemory(bytes);
    }
}
