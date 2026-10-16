package com.acme.math;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class DivisionTest {

    @Test
    void divideByZeroThrows() {
        int hits = 10;
        assertThrows(ArithmeticException.class, () -> {
            int unused = hits / 0;
        });
    }
}
