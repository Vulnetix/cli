package com.acme;

public class Shard {
    int pick(String key, int buckets) {
~>        int idx = Math.abs(key.hashCode()) % buckets;
        return idx;
    }
}
