package com.acme;

import java.util.*;

public class Safe {
    private final List<String> names = new ArrayList<>();
    private final Map<String, Integer> counts = new HashMap<>();

    void clean() {
        for (String n : new ArrayList<>(names)) {
            if (n.isEmpty()) {
                names.remove(n);
            }
        }
        Iterator<Map.Entry<String, Integer>> it = counts.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() == 0) {
                it.remove();
            }
        }
        for (String n : names) {
            if (n.equals("x")) {
                names.remove(n);
                return;
            }
        }
    }
}
