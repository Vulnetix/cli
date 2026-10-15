package com.shop.ids;

import java.util.Random;

public class Orders {
    private long lastOrder = 0;
    private final Random rnd = new Random();

    public long next() {
        long orderNumber = lastOrder + rnd.nextInt(10);
        lastOrder = orderNumber;
        return orderNumber;
    }
}
