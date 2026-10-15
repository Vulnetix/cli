package com.acme;

import java.util.ArrayList;
import java.util.List;

public class Cart {
    private final List<Item> items = new ArrayList<>();

    public void dropFree() {
        for (Item item : items) {
~>            if (item.price() == 0) items.remove(item);
        }
    }
}
