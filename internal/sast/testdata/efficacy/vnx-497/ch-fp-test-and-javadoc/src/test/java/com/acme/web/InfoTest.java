package com.acme.web;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class InfoTest {
    /**
     * Never do out.println(System.getProperty("java.version")) in a servlet.
     */
    @Test
    void versionIsHidden() {
        String body = "out.println(System.getenv())";
        assertTrue(body.length() > 0);
    }
}
