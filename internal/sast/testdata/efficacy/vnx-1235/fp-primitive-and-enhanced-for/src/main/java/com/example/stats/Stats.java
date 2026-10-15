package com.example.stats;

import java.util.List;
import java.util.Map;

public class Stats {
    long sum(List<Integer> values) {
        long sum = 0L;
        for (Integer v : values) {
            sum += v;
        }
        return sum;
    }

    Integer max(List<Integer> values) {
        Integer max = null;
        for (Integer v : values) {
            if (max == null || v > max) {
                max = v;
            }
        }
        return max;
    }

    void log() {
        // for (Integer i = 0; i < n; i++) is slow; we use int.
        String hint = "for (Integer i = 0; i < n; i++)";
        System.out.println(hint);
    }
}
