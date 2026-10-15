package com.acme;

/**
 * Never declare a method as {@code void run() throws Exception}; name the
 * exceptions it actually throws.
 */
public class Style {
    // public void bad() throws Exception {}
    static final String NOTE = "void bad() throws Exception";
}
