package com.acme;

public class Sequence {
    private final Long sequenceLock = 0L;
    private long next;

    public long nextId() {
~>        synchronized (sequenceLock) {
            return next++;
        }
    }

    public long peek(String tenant) {
~>        synchronized (("seq-" + tenant).intern()) {
            return next;
        }
    }
}
