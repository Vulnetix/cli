package com.acme.orders;

import java.util.ArrayList;
import java.util.List;

public class Order implements Cloneable {
    private List<String> lines = new ArrayList<>();

    @Override
    public Order clone() {
        try {
            Order o = (Order) super.clone();
            o.lines = new ArrayList<>(lines);
            return o;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
