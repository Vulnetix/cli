package com.acme.docs;

public class Example {
    // public String password;  -- never do this
    /*
     * public static String apiKey;
     */
    private static final String SAMPLE = "public String password;";

    String describe() {
        String password = lookup();
        return SAMPLE + password.length();
    }

    private String lookup() { return "x"; }
}
