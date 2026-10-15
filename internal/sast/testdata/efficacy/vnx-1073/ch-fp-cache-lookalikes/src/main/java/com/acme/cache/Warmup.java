package com.acme.cache;

import java.util.Map;
import java.util.concurrent.ExecutorService;

public class Warmup {
    public void warm(Map<String, String> cache, ExecutorService executor, Http http) {
        cache.put("a", http.get("/a"));
        cache.put("b", http.get("/b"));
        executor.execute(() -> cache.remove("a"));
        executor.execute(() -> cache.remove("b"));
        http.execute("/flush");
        cache.get("findAll");
        String q = "executeQuery(createQuery(save()))";
    }
}
