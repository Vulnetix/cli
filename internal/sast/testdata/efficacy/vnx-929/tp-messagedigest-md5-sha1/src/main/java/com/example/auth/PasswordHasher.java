package com.example.auth;

import java.security.MessageDigest;

public class PasswordHasher {
    private static final String LEGACY = "MD4";

    byte[] hash(String password) throws Exception {
        // MD5 and SHA-1 in a .java file are VNX-CRYPTO-001 and VNX-CRYPTO-002 findings
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes("UTF-8"));
    }

    byte[] sign(byte[] token) throws Exception {
        MessageDigest sha = java.security.MessageDigest.getInstance( "SHA-1" );
        MessageDigest legacy = MessageDigest.getInstance("sha1", "SUN");
~>        MessageDigest md2 = MessageDigest.getInstance("MD2");
~>        MessageDigest md4 = MessageDigest.getInstance(
                "MD4");
~>        MessageDigest old = MessageDigest.getInstance(LEGACY);
        return sha.digest(token);
    }
}
