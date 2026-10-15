package com.example.model;

public abstract class Entity {
    @Override
    public abstract boolean equals(Object o);

    @Override
    public abstract int hashCode();
}

class Customer extends Entity {
    private final long id;

    Customer(long id) {
        this.id = id;
    }

    @Override public boolean equals(Object o) { return o instanceof Customer c && c.id == id; }
    @Override public int hashCode() { return Long.hashCode(id); }
}
