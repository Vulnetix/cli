package com.acme.names;

public class Names {
    // Cipher.getInstance("DES") is forbidden by policy.
    static final String POLICY = "Cipher.getInstance(\"DESede\") is forbidden";
    private int desiredRounds = 3;
    private String blowfishNote = "legacy";
}
