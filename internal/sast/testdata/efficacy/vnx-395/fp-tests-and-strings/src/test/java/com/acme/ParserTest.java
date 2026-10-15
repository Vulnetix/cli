package com.acme;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class ParserTest {
    @Test
    void rejectsNull() {
        assertThrows(NullPointerException.class, () -> Parser.parse(null));
        try {
            Parser.parse(null);
        } catch (NullPointerException expected) {
        }
    }
}
