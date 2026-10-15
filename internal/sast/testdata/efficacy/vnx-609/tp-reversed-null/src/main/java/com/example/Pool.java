package com.example;

public final class Pool {
    static Pool shared;

    static Pool get() {
        if (null == shared) {
~>            synchronized (Pool.class) {
                if (null == shared) {
                    shared = new Pool();
                }
            }
        }
        return shared;
    }
}
