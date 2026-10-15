package com.example.model;

import java.util.ArrayList;
import java.util.List;

public class Order implements Cloneable {
    private int[] quantities = new int[0];
    private ArrayList<String> lines = new ArrayList<>();

    @Override
    public Order clone() {
        try {
            Order o = (Order) super.clone();
            o.quantities = quantities.clone();
            o.lines = new ArrayList<>(lines);
            return o;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

    public int[] snapshot() {
        return quantities.clone();
    }

    // a clone() without super.clone() breaks subclasses
    public List<String> copyLines() {
        return new ArrayList<>(lines);
    }
}
