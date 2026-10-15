package com.acme.order;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class Order {
    private List<LineItem> items = new ArrayList<>();
    private Set<String> tags;

    public void setItems(List<LineItem> items) {
~>        this.items = items;
    }

    public Order withTags(final Set<String> newTags) {
~>        this.tags = newTags;
        return this;
    }
}
