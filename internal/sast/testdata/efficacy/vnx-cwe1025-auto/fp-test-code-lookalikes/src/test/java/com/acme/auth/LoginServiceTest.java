package com.acme.auth;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LoginServiceTest {

    @Test
    void literalsAreInterned() {
        String a = "admin";
        // the compiler interns both literals, which is what this test pins
        assertTrue(a == "admin");
    }
}
