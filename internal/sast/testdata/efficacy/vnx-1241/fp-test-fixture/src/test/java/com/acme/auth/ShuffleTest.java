package com.acme.auth;

import java.util.Random;
import org.junit.jupiter.api.Test;

class ShuffleTest {
    @Test
    void deterministic() {
        Random r = new Random(7);
        r.setSeed(11);
    }
}
