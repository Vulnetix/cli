package com.acme.cache;

import java.util.Map;

public class Warmup {
    public void warm(Map<String, Object> cache, String prefix, int n) {
        String key;
        for (int i = 0; i < n; i++) {
            key = prefix + ":" + i;
            cache.put(key, load(key));
        }
        String msg = "warmed";
        msg += " " + n;
        System.out.println(msg);
    }

    private Object load(String k) {
        return k;
    }
}
