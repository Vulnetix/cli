package com.acme.model;

public abstract class Order implements Cloneable {
    protected List<Item> items;

    @Override
~>    public synchronized Order clone() {
        try {
            Order copy = (Order) super.clone();
            copy.items = new ArrayList<>(items);
            return copy;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
