package com.acme.order;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class Cart {
    private final List<LineItem> items = new ArrayList<>();
    private Map<String, Integer> quantities = new HashMap<>();

    public List<LineItem> getItems() {
~>        return items;
    }

    public Map<String, Integer> quantities()
    {
~>        return this.quantities;
    }
}
