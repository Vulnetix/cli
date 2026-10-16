package com.acme;

~>import sun.misc.Unsafe;
import java.lang.reflect.Field;

public class Mem {
    static Unsafe unsafe() throws Exception {
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return (Unsafe) f.get(null);
    }
}
