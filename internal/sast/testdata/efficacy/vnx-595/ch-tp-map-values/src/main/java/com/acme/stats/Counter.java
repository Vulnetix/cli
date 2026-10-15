package com.acme.stats;

import java.util.Map;

public class Counter {
    boolean unchanged(Map<String, Integer> before, Map<String, Integer> after, String key) {
        Integer previous = before.get(key);
        Integer current = after.get(key);
~>        if (previous != current) {
            return false;
        }
        return true;
    }
}
