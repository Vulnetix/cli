package com.acme.vault;

import org.junit.jupiter.api.Test;

class VaultTest {
    private String masterPassword = "test-only";

    class Fixture {
        String pw() { return masterPassword; }
    }

    @Test
    void unlocks() {
        new Fixture().pw();
    }
}
