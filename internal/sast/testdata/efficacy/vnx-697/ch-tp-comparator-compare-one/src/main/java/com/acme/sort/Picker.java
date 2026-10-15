package com.acme.sort;

import java.util.Comparator;

public class Picker<T> {
    private final Comparator<T> order;

    public Picker(Comparator<T> order) {
        this.order = order;
    }

    public T max(T x, T y) {
~>        return order.compare(x, y) == 1 ? x : y;
    }
}
