package com.acme.metrics;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class Peaks {

    Integer peak(List<Integer> values) {
        Integer max = null;
        for (Integer v : values) {
            if (max == null || v > max) {
                max = v;
            }
        }
        return max;
    }

    int hits(List<String> lines) {
        AtomicInteger counter = new AtomicInteger(0);
        for (String line : lines) {
            if (line.contains("GET")) {
                counter.incrementAndGet();
            }
        }
        return counter.get();
    }
}
