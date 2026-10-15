package com.acme;

import java.security.SecureRandom;
import java.util.List;

public class Pick {
    private final SecureRandom rnd = new SecureRandom();

    public String pick(List<String> items) {
        return items.get(rnd.nextInt(items.size()));
    }

    public byte[] token() {
        byte[] token = new byte[32];
        rnd.nextBytes(token);
        return token;
    }
}
