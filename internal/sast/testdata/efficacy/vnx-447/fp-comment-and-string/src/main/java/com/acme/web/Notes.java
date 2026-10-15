package com.acme.web;

public class Notes {
    // @PostMapping handlers must never just "throw new UnsupportedOperationException()"
    static final String HINT = "public void setEncryptionEnabled(boolean e) { }";

    /*
     * public boolean changePassword(String u) { return true; }
     */
    int size() { return 0; }
}
