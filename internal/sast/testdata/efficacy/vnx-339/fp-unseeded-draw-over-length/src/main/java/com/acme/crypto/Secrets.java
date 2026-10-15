package com.acme.crypto;

import java.security.SecureRandom;
import java.util.Random;

public class Secrets {
    static final String[] SECRETS = {"a", "b", "c"};

    public String secret() {
        String secret = SECRETS[new Random().nextInt(SECRETS.length)];
        return secret;
    }

    public int prime() {
        return new SecureRandom().nextInt(SECRETS.length);
    }
}
