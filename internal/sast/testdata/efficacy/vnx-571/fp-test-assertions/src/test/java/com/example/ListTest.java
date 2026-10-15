package com.example;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ListTest {
    @Test
    void sizeIsNonNegative() {
        List<String> l = List.of();
        assertTrue(l.size() >= 0);
    }
}
