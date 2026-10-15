package com.acme.auth;

public class Signer {
    private String secret;

    Runnable task() {
        return () -> sign(secret);
    }

    static class Helper {
        private String secret;

        String get() { return secret; }
    }
}
