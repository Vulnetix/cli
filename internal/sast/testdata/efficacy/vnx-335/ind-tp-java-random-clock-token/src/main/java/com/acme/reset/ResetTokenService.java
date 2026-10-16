package com.acme.reset;

import java.util.Random;

public class ResetTokenService {
~>    private final Random random = new Random(System.currentTimeMillis());

    public String generateResetToken() {
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 24; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }
}
