package com.example;

public class Registry {
    private static Registry instance;

    public static Registry getInstance() {
        if (instance == null) {
~>            synchronized (Registry.class) {
                if (instance == null) {
                    instance = new Registry();
                }
            }
        }
        return instance;
    }
}
