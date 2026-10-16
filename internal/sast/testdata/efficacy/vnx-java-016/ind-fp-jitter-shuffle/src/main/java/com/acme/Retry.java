package com.acme;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class Retry {
    public long backoffMillis(int attempt) {
        long jitter = ThreadLocalRandom.current().nextLong(0, 250);
        return (1L << attempt) * 100 + jitter;
    }

    public <T> void mix(List<T> items) {
        Collections.shuffle(items, new Random());
    }

    public Object sample(List<Object> xs) {
        return xs.get(new Random().nextInt(xs.size()));
    }
}
