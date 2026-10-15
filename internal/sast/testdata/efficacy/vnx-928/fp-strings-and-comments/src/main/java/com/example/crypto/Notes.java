package com.example.crypto;

public class Notes {
    // Never call Cipher.getInstance("DES") here: it is broken.
    /* Cipher.getInstance("RC4") was removed in 2019. */
    static final String HELP = "DES and RC4 are not supported";
    static final String MODE_DESCRIPTION = "DESCRIPTION";
    void log() {
        System.out.println("Refusing DES, RC4 and DESede ciphers");
    }
}
