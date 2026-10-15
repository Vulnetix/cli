package com.acme.io;

import org.junit.jupiter.api.Test;

class ReaderTest {
    @Test
    void readsNothing() {
        try {
            new Reader().read(null);
        } catch (NullPointerException e) {
        }
    }
}
