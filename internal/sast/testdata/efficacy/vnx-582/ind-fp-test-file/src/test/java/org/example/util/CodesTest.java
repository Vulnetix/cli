package org.example.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class CodesTest {
    public static final int[] EXPECTED = {1, 2, 3};

    @Test
    void returnsCopy() {
        assertArrayEquals(EXPECTED, Codes.codes());
    }
}
