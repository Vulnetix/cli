package com.acme;

public class Thing {
    private String id;
    private Thing delegate;

    public String getId() {
        return this.id;
    }

    public String getName() {
        return delegate.getName();
    }

    public int count(long n) {
        return count((int) n);
    }

    public int count(int n) {
        return n;
    }

    public String describe() {
        return super.toString();
    }
    // public String getX() { return getX(); }
}
