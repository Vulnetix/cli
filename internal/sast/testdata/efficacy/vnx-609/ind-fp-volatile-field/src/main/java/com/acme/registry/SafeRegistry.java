package com.acme.registry;

public final class SafeRegistry {

    private static volatile SafeRegistry instance;

    private SafeRegistry() {
    }

    public static SafeRegistry getInstance() {
        if (instance == null) {
            synchronized (SafeRegistry.class) {
                if (instance == null) {
                    instance = new SafeRegistry();
                }
            }
        }
        return instance;
    }
}
