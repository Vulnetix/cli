package com.acme.docs;

public class Guide {
    // for (...) { if (mac[i] != expected[i]) return false; } leaks timing.
    static final String BAD = "for (int i = 0; i < n; i++) { if (token[i] != given[i]) return false; }";

    public boolean constantTime(byte[] mac, byte[] expected) {
        int diff = mac.length ^ expected.length;
        for (int i = 0; i < mac.length && i < expected.length; i++) {
            diff |= mac[i] ^ expected[i];
        }
        return diff == 0;
    }
}
