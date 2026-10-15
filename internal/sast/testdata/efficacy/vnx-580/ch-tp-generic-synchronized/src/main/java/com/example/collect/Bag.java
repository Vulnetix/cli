package com.example.collect;

import java.util.ArrayList;
import java.util.List;

public class Bag<T> implements Cloneable {
    private List<T> items = new ArrayList<>();

    public void add(T item) {
        items.add(item);
    }

    @Override
~>    public synchronized Bag<T> clone() {
        Bag<T> copy = new Bag<>();
        copy.items = new ArrayList<>(items);
        return copy;
    }
}
