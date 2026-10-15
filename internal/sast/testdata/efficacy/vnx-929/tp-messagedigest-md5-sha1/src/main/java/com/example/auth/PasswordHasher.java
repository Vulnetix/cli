package com.example.auth;

import java.security.MessageDigest;

public class PasswordHasher {
    byte[] hash(String password) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes("UTF-8"));
    }

    byte[] sign(byte[] token) throws Exception {
~>        MessageDigest sha = java.security.MessageDigest.getInstance( "SHA-1" );
~>        MessageDigest legacy = MessageDigest.getInstance("sha1", "SUN");
~>        MessageDigest md2 = MessageDigest.getInstance("MD2");
        return sha.digest(token);
    }
}
