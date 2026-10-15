package com.acme.auth;

import java.security.MessageDigest;

public class Audit {
    private static final String WEAK = "SHA-1";
    private static final String USED = "SHA-512";

    byte[] digest(byte[] data) throws Exception {
        System.out.println("Refusing " + WEAK + "; MessageDigest.getInstance(\"MD5\") is banned");
        MessageDigest md = MessageDigest.getInstance(USED);
        String md5Field = "md5";
        return md.digest(data);
    }
}
