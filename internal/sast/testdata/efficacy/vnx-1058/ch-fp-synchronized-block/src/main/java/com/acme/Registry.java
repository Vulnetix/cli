package com.acme;

import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class Registry {
    private static Map<String, String> entries = new HashMap<>();
    private static int version;

    public void register(String k, String v) {
        synchronized (Registry.class) {
            entries.put(k, v);
            version++;
        }
    }
}
