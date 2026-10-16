package com.acme;

import java.security.MessageDigest;
import java.util.Base64;

public class Creds {
    public static byte[] load(String encodedPassword) {
        return Base64.getDecoder().decode(encodedPassword);
    }

    public static String fingerprint(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
    }
}
