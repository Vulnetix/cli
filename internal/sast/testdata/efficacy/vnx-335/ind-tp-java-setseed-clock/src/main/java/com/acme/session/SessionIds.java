package com.acme.session;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class SessionIds {
    private final SecureRandom sr;

    public SessionIds() throws NoSuchAlgorithmException {
        sr = SecureRandom.getInstance("SHA1PRNG");
~>        sr.setSeed(System.currentTimeMillis());
    }

    public String next() {
        byte[] id = new byte[16];
        sr.nextBytes(id);
        return HexFormat.of().formatHex(id);
    }
}
