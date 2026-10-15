package com.acme;

import static org.junit.jupiter.api.Assertions.assertThrows;

class MathTest {
    void divides() {
        // int x = 1 / 0;
        assertThrows(ArithmeticException.class, () -> { int y = 1 / 0; });
    }
}
