package com.acme.pool;

public class Slab {
    private int refCount = 1;

    public void retain() {
~>        refCount++;
    }

    public void release() {
~>        if (--refCount == 0) {
            free();
        }
    }

    private void free() {}
}
