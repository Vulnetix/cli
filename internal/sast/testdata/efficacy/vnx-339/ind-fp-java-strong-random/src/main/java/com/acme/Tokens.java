package com.acme;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class Tokens {
    public String newSessionToken(String user) throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] token = new byte[Math.max(32, user.length())];
        sr.nextBytes(token);
        return HexFormat.of().formatHex(token);
    }
}
