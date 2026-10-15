package com.example;

import java.util.Map;

public class Loader {
    private boolean initialized = false;
    private Map<String, String> table;
    private final Object lock = new Object();

    public Map<String, String> table() {
        if (!initialized) {
~>            synchronized (lock) {
                if (!initialized) {
                    table = load();
                    initialized = true;
                }
            }
        }
        return table;
    }

    public Map<String, String> other() {
        if (this.table == null)
        {
~>            synchronized(this) {
                // second check under the lock
                if (this.table == null) {
                    this.table = load();
                }
            }
        }
        return table;
    }
}
