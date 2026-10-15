package com.acme.util;

import java.util.List;

public class Clock {

    public int seed() {
        return (int) System.currentTimeMillis();
    }

    public int count(List<String> xs) {
        long total = xs.size();
        return (int) (total * 2);
    }

    public int ratio(double d) {
        return (int) d;
    }
}
