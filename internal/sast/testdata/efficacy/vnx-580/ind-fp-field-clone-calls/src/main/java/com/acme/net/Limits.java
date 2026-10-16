package com.acme.net;

public class Limits {
    private int[] limits = {1, 2, 3};
    private java.util.Date created = new java.util.Date();

    public int[] snapshot() {
        return limits.clone();
    }

    public java.util.Date createdAt() {
        return (java.util.Date) created.clone();
    }

    // public Limits clone() { return new Limits(); } was removed
}
