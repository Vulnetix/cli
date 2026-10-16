package com.acme.sec;

public class Session implements Cloneable {
    private byte[] token;

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}

class Ticket {
    @Override
    public final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }
}

record Range(int lo, int hi) {
}
