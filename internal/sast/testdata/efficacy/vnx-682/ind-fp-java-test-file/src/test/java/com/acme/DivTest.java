package com.acme;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DivTest {
    @Test
    void divideByZeroThrows() {
        int x = 5;
        assertThrows(ArithmeticException.class, () -> { int y = x / 0; });
    }
}
