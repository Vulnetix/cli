package com.acme.stats;

public class Limits {
    boolean atLimit(Integer used, int max) {
        long total = used;
        return used == max && total == 10L;
    }
}
