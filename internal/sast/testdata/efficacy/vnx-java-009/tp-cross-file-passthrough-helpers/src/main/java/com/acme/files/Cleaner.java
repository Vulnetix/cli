package com.acme.files;

public class Cleaner {
    // Looks like a filter, but the result never depends on the input.
    public String clean(String raw) {
        return "clean";
    }

    public String choose(String first, String second) {
        return second;
    }
}
