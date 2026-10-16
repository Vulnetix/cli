package com.acme;

public class Loader {
    static Object PLUGIN;

    static {
        try {
            PLUGIN = Class.forName("com.acme.Plugin").getDeclaredConstructor().newInstance();
~>        } catch (ReflectiveOperationException e) {
            System.err.println("plugin failed: " + e);
        }
    }
}
