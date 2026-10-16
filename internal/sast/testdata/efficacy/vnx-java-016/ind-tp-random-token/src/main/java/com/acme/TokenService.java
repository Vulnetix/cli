package com.acme;

import java.util.Random;

public class TokenService {
    private final Random random = new Random();

    public String newSessionToken() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
~>            sb.append(Integer.toHexString(random.nextInt(16)));
        }
        String sessionToken = sb.toString();
        return sessionToken;
    }
}
