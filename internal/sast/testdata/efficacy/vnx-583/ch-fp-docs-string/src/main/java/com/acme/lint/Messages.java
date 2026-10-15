package com.acme.lint;

public class Messages {
    // Never write public void finalize() in this codebase.
    static final String HINT = "public void finalize() should be protected";
    /*
     * public void finalize() {
     * }
     */
}
