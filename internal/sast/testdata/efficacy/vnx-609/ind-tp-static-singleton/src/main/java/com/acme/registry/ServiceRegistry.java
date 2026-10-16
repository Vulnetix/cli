package com.acme.registry;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class ServiceRegistry {

    private static ServiceRegistry instance;

    private final Map<String, Object> services = new ConcurrentHashMap<>();

    private ServiceRegistry() {
        services.put("clock", System.class);
    }

    public static ServiceRegistry getInstance() {
        if (instance == null) {
~>            synchronized (ServiceRegistry.class) {
                if (instance == null) {
                    instance = new ServiceRegistry();
                }
            }
        }
        return instance;
    }

    public Object lookup(String name) {
        return services.get(name);
    }
}
