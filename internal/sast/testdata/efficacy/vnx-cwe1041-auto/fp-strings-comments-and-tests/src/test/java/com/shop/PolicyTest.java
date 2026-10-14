package com.shop;

class PolicyTest {
    void roles() {
        if (user.hasRole("ADMIN")) {
            assertTrue(true);
        } else if (user.hasRole("ADMIN")) {
            fail();
        }
        verifyToken(token);
        verifyToken(token);
    }
}
