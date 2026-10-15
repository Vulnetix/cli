package com.acme;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class Shuffle {
    private final SecureRandom secureRandom = new SecureRandom();

    public void order(List<String> items) {
        Random shuffler = new Random(7);
        Collections.shuffle(items, shuffler);
    }

    public byte[] salt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }
}
