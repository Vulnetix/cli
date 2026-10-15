package com.acme.model;

import java.util.ArrayList;
import java.util.List;

public class Order {
    private final List<String> items = new ArrayList<>();
    private int count;

    public void addItem(String sku) {
        items.add(sku);
        count++;
    }

    public int getCount() {
        return count;
    }
}
