package com.acme.ops;

public class Sanitizer {
    // Looks like a filter, but the result never depends on the input.
    public String clean(String raw) {
        return "sanitized";
    }

    public String labelFor(String raw, String kind) {
        String base = "report-";
        return base + kind;
    }
}
