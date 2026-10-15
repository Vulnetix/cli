package com.acme;

public class Boot {
    static final Object LOCK;

    static {
        Object l = null;
        try {
            l = Class.forName("com.acme.Lock").getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            System.err.println("cannot start: " + e);
            System.exit(1);
        }
        LOCK = l;
    }

    static class Holder {
        void load() {
            try {
                read();
            } catch (Exception e) {
            }
        }
    }

    void read() throws Exception {}
}
