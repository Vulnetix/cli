package com.example;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;
import org.junit.jupiter.api.Test;

class SizeTest {
    @Test
    void neverNegative() {
        List<String> l = List.of("a");
        assertFalse(l.size() < 0);
    }
}
