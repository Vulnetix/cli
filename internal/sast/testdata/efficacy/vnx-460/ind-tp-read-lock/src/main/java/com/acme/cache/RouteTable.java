package com.acme.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RouteTable {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, Route> routes = new HashMap<>();

    public Route resolve(String host) {
~>        rw.readLock().lock();
        Route r = routes.get(host.toLowerCase());
        Route resolved = r.withDefaults();
        rw.readLock().unlock();
        return resolved;
    }
}
