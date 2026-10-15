package com.example;

import java.util.Random;

public class Shards {
    private final Random random = new Random();

    public int shardFor(String key, int shards) {
~>        return Math.abs(key.hashCode()) % shards;
    }

    public int pick(Object[] items) {
~>        int idx = Math.abs(random.nextInt()) % items.length;
~>        long slot = Math.abs( rng().nextLong() ) % 1024;
~>        int h = Math.abs(hashCode());
        return idx + (int) slot + h;
    }

    private Random rng() { return random; }
}
