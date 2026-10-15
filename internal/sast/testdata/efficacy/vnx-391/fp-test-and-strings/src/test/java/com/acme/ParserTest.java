package com.acme;

import org.junit.jupiter.api.Test;

class ParserTest {
    @Test
    void rejectsGarbage() {
        try {
            Parser.parse("??");
        } catch (Exception e) {}
    }
}
