package com.example;

import static org.junit.jupiter.api.Assertions.assertThrows;

class MathTest {
    void dividesByZero() {
        int one = 1;
        assertThrows(ArithmeticException.class, () -> System.out.println(one / 0));
    }
}
