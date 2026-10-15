package com.acme.stats;

import java.util.List;

public class Stats {
    public String label(List<String> parts) {
        String total = String.join("+", parts);
        return total;
    }

    public long sum(List<Long> values) {
        long total = 0;
        for (long v : values) {
            total += v;
        }
        return total;
    }

    public String join(List<String> values) {
        StringBuilder sb = new StringBuilder();
        String sep = "";
        for (String v : values) {
            sb.append(sep).append(v);
            sep = ",";
        }
        return sb.toString();
    }
}
