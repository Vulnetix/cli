package com.acme;

import java.security.SecureRandom;
import java.util.Base64;

public class Tokens {
    private static final SecureRandom RNG = new SecureRandom();

    public static String resetToken() {
~>        byte[] tokenBytes = new byte[6];
        RNG.nextBytes(tokenBytes);
        return @@sample:B[a]se[6]4[.][g]et[U]rl[E]nc[o]de[r]@@().withoutPadding().encodeToString(tokenBytes);
    }
}
