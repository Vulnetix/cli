package com.acme.sim;

import java.util.Random;

public class Sim {
    public String run(long configuredSeed) {
        long seed = System.currentTimeMillis();
        Random rnd = new Random(seed);
        int roll = rnd.nextInt(6);
        Random other = new Random(configuredSeed);
        String sessionToken = Long.toHexString(other.nextLong());
        return roll + sessionToken;
    }
}
