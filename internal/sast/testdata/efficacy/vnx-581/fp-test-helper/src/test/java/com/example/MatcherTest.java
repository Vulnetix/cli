package com.example;

import org.junit.jupiter.api.Test;

class MatcherTest {
    static class AnyString {
        @Override
        public boolean equals(Object o) {
            return o instanceof String;
        }
    }

    @Test
    void matches() {
        new AnyString().equals("x");
    }
}
