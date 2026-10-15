package com.shop;

import java.util.Random;

class TokenTest {
    void fuzzTokens() {
        Random r = new Random(System.currentTimeMillis());
        String token = Long.toHexString(r.nextLong());
        assert token.length() > 0;
    }
}
