package com.acme.net;

public class SharedBuffer {
    private int refCount = 1;
    private volatile long refCnt;

    public SharedBuffer retain() {
~>        refCount++;
~>        this.refCnt += 1;
        return this;
    }

    public void release() {
~>        if (--refCount == 0) {
            free();
        }
    }

    private void free() {
    }
}
