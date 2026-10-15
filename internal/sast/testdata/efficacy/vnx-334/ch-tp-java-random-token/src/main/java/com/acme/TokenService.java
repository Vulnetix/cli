package com.acme;

import java.security.SecureRandom;
import java.util.Random;

public class TokenService {
    private final Random rnd = new Random();
    private final SecureRandom secure = new SecureRandom();

    public String issueToken() {
~>        String token = String.valueOf(new Random().nextInt(100000));
        return token;
    }

    public int sessionKey() {
~>        int sessionKey = secure.nextInt(65536);
        return sessionKey;
    }
}
