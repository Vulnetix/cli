package com.acme.lb;

import java.util.Random;

public class Picker {
    private final Random random = new Random();

    public String pick(String[] items) {
~>        int idx = Math.abs(random.nextInt()) % items.length;
        return items[idx];
    }

    public long window(long sum) {
~>        long bucket = sum % 0L;
        return bucket;
    }
}
