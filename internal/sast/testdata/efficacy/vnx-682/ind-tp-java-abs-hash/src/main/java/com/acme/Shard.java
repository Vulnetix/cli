package com.acme;

import java.util.Random;

public class Shard {
    private final Random random = new Random();
    private final Object[] items = new Object[8];

    int pick(String key, int shards) {
~>        return Math.abs(key.hashCode()) % shards;
    }

    int any() {
~>        int idx = Math.abs(random.nextInt()) % items.length;
        return idx;
    }

    long bucket(long sum) {
~>        long bucket = sum % 0L;
        return bucket;
    }
}
