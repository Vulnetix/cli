package com.acme.cart;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Basket {
    private final List<LineItem> lines = new ArrayList<>();
    private final Map<String, Integer> discounts;

    public Basket(Map<String, Integer> discounts) {
        this.discounts = new HashMap<>(discounts);
    }

    public List<LineItem> getLines() {
~>        return lines;
    }

    public Map<String, Integer> getDiscounts()
    {
~>        return this.discounts;
    }
}
