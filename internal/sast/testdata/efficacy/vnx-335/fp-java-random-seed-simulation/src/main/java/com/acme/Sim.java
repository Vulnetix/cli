package com.acme;

import java.util.Random;

public class Sim {
    private final Random random = new Random(42);

    public double step() {
        return random.nextGaussian();
    }
}
