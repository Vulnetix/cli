package com.example.crypto;

import java.security.MessageDigest;

public class Describe {
    static final String DESCRIPTOR = "DESCRIPTOR";
    String DESIGNER = "RC4X";
    Object x() throws Exception {
        Object d = DesignFactory.getInstance("DESIGN");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Registry.getInstance(DESCRIPTOR);
    }
}
