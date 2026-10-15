package com.acme.sync;

public class Init {
    static void touch() {
~>        synchronized (Init.class) {
        }
    }
}
