package com.acme;

import java.security.SecureRandom;

public class Sessions {
    private final SecureRandom rnd = new SecureRandom();

    public String newSession() {
~>        int sessionId = rnd.nextInt(100000);
        return Integer.toString(sessionId);
    }

    public String resetToken() {
~>        String token = String.valueOf(rnd.nextInt());
        return token;
    }
}
