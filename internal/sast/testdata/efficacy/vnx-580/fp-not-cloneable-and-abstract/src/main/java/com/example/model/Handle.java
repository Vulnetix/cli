package com.example.model;

public class Handle {
    private final long fd;

    public Handle(long fd) {
        this.fd = fd;
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("handles are unique");
    }

    public abstract static class Shape implements Cloneable {
        @Override
        public abstract Shape clone();
    }

    interface Copyable {
        Copyable clone();
    }

    static class Immutable implements Cloneable {
        @Override
        public Immutable clone() {
            return this;
        }
    }
}
