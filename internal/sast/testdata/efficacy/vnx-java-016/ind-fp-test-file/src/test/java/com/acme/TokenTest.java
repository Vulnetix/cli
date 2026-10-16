package com.acme;

import java.util.Random;
import org.junit.jupiter.api.Test;

class TokenTest {
    @Test
    void fixtureToken() {
        Random random = new Random(42);
        String token = "t" + random.nextInt(1000);
    }
}
