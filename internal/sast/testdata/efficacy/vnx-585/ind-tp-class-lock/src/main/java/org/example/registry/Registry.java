package org.example.registry;

public final class Registry {
    public static void touch() {
~>        synchronized (Registry.class) { /* intentionally empty */ }
    }
}
