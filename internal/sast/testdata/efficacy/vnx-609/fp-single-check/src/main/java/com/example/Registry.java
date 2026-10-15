package com.example;

public class Registry {
    private static Registry instance;

    public static synchronized Registry getInstance() {
        if (instance == null) {
            instance = new Registry();
        }
        return instance;
    }

    public void reset() {
        synchronized (Registry.class) {
            if (instance == null) {
                return;
            }
            instance = null;
        }
    }
}
