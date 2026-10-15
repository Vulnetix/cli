package com.acme.stats;

public class Quota {
    Integer cached(Integer total) {
        return total;
    }

    boolean full(int total, int limit) {
        return total == limit;
    }
}
