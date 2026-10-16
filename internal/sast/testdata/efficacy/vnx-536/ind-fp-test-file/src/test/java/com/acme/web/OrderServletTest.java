package com.acme.web;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.Test;

class OrderServletTest {

    @Test
    void writesErrors() throws Exception {
        StringWriter body = new StringWriter();
        PrintWriter writer = new PrintWriter(body);
        try {
            throw new IllegalStateException("boom");
        } catch (IllegalStateException e) {
            writer.println("Error: " + e.getMessage());
            e.printStackTrace(writer);
        }
        assertTrue(body.toString().contains("boom"));
    }
}
