package com.acme;

public class SharedBuffer {
    private int refCount = 1;

    public SharedBuffer retain() {
~>        refCount++;
        return this;
    }
}
