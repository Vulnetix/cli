package com.acme.cache;

public class Entry {
    @SuppressWarnings("deprecation")
~>    public void finalize() {
        Registry.remove(this);
    }
}
