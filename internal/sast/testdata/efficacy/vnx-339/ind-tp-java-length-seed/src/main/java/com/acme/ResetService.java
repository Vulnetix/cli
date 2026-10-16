package com.acme;

import java.util.Random;

public class ResetService {
    public String createResetToken(String email) {
        Random random = new Random();
~>        random.setSeed(email.length());
        long token = random.nextLong();
        return Long.toHexString(token);
    }
}
