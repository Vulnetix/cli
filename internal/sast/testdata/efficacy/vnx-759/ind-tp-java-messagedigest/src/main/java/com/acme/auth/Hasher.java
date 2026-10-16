package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Hasher {
    public byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
~>        return md.digest(password.getBytes(StandardCharsets.UTF_8));
    }
}
