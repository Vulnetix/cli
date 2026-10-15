package com.acme.cart;

import java.util.List;

public class Cart {
    public long total(List<Item> items) {
        long sum = 0;
~>        for (Item item : items);
        {
            sum += 1;
        }
        return sum;
    }
}
