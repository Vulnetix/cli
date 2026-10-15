package com.acme.security;

import java.util.concurrent.ThreadLocalRandom;

public class CodeGenerator {
    public String generatePasswordResetCode() {
~>        return String.valueOf(ThreadLocalRandom.current().nextInt(100000, 999999));
    }

    public String generateApiKey() {
~>        return Long.toString(Math.abs(ThreadLocalRandom.current().nextLong()), 36);
    }
}
