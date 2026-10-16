package com.acme.sim;

import java.util.Random;

public class LoadSimulator {
    private final Random random = new Random(42L);

    public int nextArrivalMillis() {
        return 50 + random.nextInt(200);
    }
}
