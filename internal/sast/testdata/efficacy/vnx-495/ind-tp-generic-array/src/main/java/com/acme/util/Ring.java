package com.acme.util;

public class Ring<T> {
    private final Object[] slots;
    private long[] timestamps;

    public Ring(int n) {
        slots = new Object[n];
        timestamps = new long[n];
    }

    public Object[] snapshot() {
~>        return slots;
    }

    @Override
    public String toString() {
        return "Ring(" + slots.length + ")";
    }

    public final long[] getTimestamps()
    {
~>        return this.timestamps;
    }
}
