package com.acme.pool;

import java.util.ArrayList;
import java.util.List;

public class ResourcePool {
    private final List<PooledResource> idle = new ArrayList<>();

    public void evictAll() throws Throwable {
        for (PooledResource r : idle) {
~>            r.finalize();
        }
        idle.clear();
    }

    public void evictCurrent() throws Throwable {
~>        current().finalize();
    }

    public void shutdown() throws Throwable {
~>        this.finalize();
    }

    private PooledResource current() {
        return idle.get(0);
    }
}
