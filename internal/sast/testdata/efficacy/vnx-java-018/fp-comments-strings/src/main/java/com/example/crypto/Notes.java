package com.example.crypto;

import javax.crypto.Cipher;

public class Notes {
    // Do not use Cipher.getInstance("RSA/ECB/PKCS1Padding"); it is vulnerable to Bleichenbacher.
    /*
     * Cipher.getInstance("RSA") defaults to PKCS#1 v1.5.
     */
    private static final String HELP = "Replace Cipher.getInstance(\"RSA/ECB/PKCS1Padding\") with OAEP";

    public String help() {
        return HELP;
    }

    public Cipher pick(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }
}
