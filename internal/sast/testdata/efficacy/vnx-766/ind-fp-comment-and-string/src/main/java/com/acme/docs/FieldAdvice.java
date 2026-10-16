package com.acme.docs;

public class FieldAdvice {
    // Do not write: public String password;
    /*
     * public PrivateKey signingKey;  <- this is what CWE-766 warns about
     */
    private static final String EXAMPLE = "public String password;";

    public String example() {
        return EXAMPLE;
    }
}
