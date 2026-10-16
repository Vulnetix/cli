package com.acme.cache;

import java.util.List;

public class ShardRouter {
    private final List<Shard> shards;

    public ShardRouter(List<Shard> shards) {
        this.shards = shards;
    }

    public Shard route(String key) {
~>        int idx = Math.abs(key.hashCode()) % shards.size();
        return shards.get(idx);
    }

    static int partition(Object key, int shards) {
~>        return Math.abs(key.hashCode()) % shards;
    }
}
