package com.acme;

import java.util.concurrent.ThreadLocalRandom;

public class ResetLink {
    public String createResetToken(String email) {
~>        long resetToken = ThreadLocalRandom.current().nextLong();
        return "https://acme.example/reset?t=" + Long.toHexString(resetToken);
    }
}
