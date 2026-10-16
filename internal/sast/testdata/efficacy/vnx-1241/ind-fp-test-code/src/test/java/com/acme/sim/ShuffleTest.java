package com.acme.sim;

import java.util.Random;
import org.junit.jupiter.api.Test;

class ShuffleTest {
    @Test
    void deterministicShuffle() {
        Random r = new Random(1234L);
        r.setSeed(99L);
    }
}
