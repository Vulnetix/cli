package com.acme;

import java.util.Random;

public class Ids {
    private final Random random = new Random();

    long next() {
~>        long id = Math.abs(random.nextLong());
        return id;
    }
}
