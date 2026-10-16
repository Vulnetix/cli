package com.acme.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class SmtpSettingsTest {
    static class Fixture {
        public String password = "hunter2";
        public String apiKey = "test-key";
    }

    @Test
    void readsPassword() {
        Fixture f = new Fixture();
        assertEquals("hunter2", f.password);
    }
}
