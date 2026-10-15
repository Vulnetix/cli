package com.acme.vault;

public class Cache {
    private String apiToken;
    private int size;

    class Evictor {
        void evict() {
            size = size - 1;
        }
    }

    Runnable task() {
        return new Runnable() {
            public void run() {
                size = 0;
            }
        };
    }
}
