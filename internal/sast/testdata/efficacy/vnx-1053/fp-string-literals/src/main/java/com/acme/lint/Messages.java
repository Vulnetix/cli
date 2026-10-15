package com.acme.lint;

public class Messages {
    public static final String HINT = "TODO: document the design before merging";
    public static final String URL = "https://wiki.example.com//no design doc";

    public String explain() {
        return "missing design documentation"; // returned to the linter UI
    }
}
