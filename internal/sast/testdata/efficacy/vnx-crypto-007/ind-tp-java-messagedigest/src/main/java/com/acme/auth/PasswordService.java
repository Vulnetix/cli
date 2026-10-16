package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class PasswordService {
    public String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
~>        byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashed);
    }
}
