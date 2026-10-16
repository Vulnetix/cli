package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class Registry {
    private final Map<String, Entry> entries = new HashMap<>();
    private final List<String> names = new ArrayList<>();

    void trim(int limit) {
        for (Map.Entry<String, Entry> e : entries.entrySet()) {
            if (e.getValue().size() > limit) {
~>                entries.remove(e.getKey());
            }
        }
    }

    void dedupe() {
        for (String n : names) {
            if (n.isEmpty()) {
~>                names.removeIf(String::isEmpty);
            }
        }
    }
}
