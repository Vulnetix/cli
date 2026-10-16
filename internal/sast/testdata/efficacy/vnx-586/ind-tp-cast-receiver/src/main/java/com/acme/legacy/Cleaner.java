package com.acme.legacy;

import java.util.Map;

public final class Cleaner {
    public static void drop(Map<String, Object> handles, String key) throws Throwable {
        Object h = handles.remove(key);
        if (h instanceof NativeHandle) {
~>            ((NativeHandle) h).finalize();
        }
    }
}
