package com.acme.util;

class SanitizerTest {
    @Test
    void bypass() {
        String attack = "....//".replace("../", "");
        assertEquals("../", attack);
    }
}
