package com.acme.core;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class MoneyTest {
    @Test
    void rejectsNullCurrency() {
        assertThrows(NullPointerException.class, () -> new Money(null, 1));
    }

    @Test
    void legacyCatch() {
        try {
            new Money(null, 1);
        } catch (NullPointerException e) {
            return;
        }
    }
}
