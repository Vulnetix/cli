package com.example.cache;

import java.util.List;

public class Warmup {
    public void warm(List<String> keys, Cache cache) {
        new Thread(() -> {
            for (String k : keys) {
                cache.load(k);
            }
~>        }).run();
    }
}
