package com.acme.files;

public class Notes {
    // new byte[(int) file.length()] truncates files over 2 GB
    /* (int) Files.size(p) */
    static final String HINT = "(int) upload.getSize() overflows";
}
