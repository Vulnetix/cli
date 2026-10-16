package com.acme.reports;

public class Quoter {
    // Never echoes its input: every caller gets the same placeholder.
    public String quote(String raw) {
        return "'redacted'";
    }

    public String column(String raw, String fallback) {
        return fallback;
    }
}
