package com.acme;

public class Cache {
    public void load(Integer key) {
~>        synchronized (key) {
            fetch(key);
        }
    }
    private void fetch(Integer k) {}
}
