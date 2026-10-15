package com.acme.cart;

import java.util.List;

public class Cart {

    long weight(List<Item> items) {
        Long grams = 0L;
~>        for (Item it : items) grams += it.getGrams();
        return grams;
    }

    int retries(Client c) {
        Integer attempts = 0;
~>        while (!c.connect() && attempts < 5) attempts++;
        return attempts;
    }
}
