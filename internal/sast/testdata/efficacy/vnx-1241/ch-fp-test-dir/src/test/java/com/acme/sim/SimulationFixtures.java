package com.acme.sim;

import java.util.Random;

public class SimulationFixtures {
    static final Random FIXED = new Random(1234L);

    static int next() {
        return FIXED.nextInt(100);
    }
}
