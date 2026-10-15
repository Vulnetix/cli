package com.example.stats;

import java.util.List;

public class Counter {
    private Long total = 0L;
    private static final Integer LIMIT = 100;

    void add(List<Long> values) {
        Integer seen = null;
        for (Long v : values) {
            if (seen == null) {
                seen = 1;
            }
            if (v > LIMIT) {
                break;
            }
        }
    }
}
