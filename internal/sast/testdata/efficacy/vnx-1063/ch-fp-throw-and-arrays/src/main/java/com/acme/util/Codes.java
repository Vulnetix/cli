package com.acme.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Codes {
    static final Map<String, List<String>> BY_GROUP;
    static final String[] NAMES;

    static {
        Map<String, List<String>> m = new HashMap<String, List<String>>();
        NAMES = new String[] {"a", "b"};
        int[] sizes = new int[4];
        if (sizes.length == 0) {
            throw new IllegalStateException("no sizes");
        }
        if (NAMES.length > 9) {
            throw new AssertionError("too many");
        }
        BY_GROUP = Collections.unmodifiableMap(m);
    }
}
