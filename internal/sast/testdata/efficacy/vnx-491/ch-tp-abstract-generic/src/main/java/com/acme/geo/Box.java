package com.acme.geo;

public abstract class Box<T extends Comparable<T>> implements Cloneable {
    protected T value;

    @SuppressWarnings("unchecked")
~>    public Box<T> clone() {
        try {
            return (Box<T>) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException(e);
        }
    }
}
